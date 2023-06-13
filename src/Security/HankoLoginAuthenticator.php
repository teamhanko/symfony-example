<?php

declare(strict_types=1);

namespace App\Security;

use App\Exception\InvalidPayloadException;
use App\Exception\InvalidTokenException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Psr\Log\LoggerInterface;
use Strobotti\JWK\KeyConverter;
use Strobotti\JWK\KeySetFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class HankoLoginAuthenticator extends AbstractAuthenticator
{

    public function __construct(
        private HttpUtils $httpUtils,
        private LoggerInterface $logger,
        private HttpClientInterface $client,
        private string $hankoApiUrl
    ) {}

    public function supports(Request $request): bool
    {
        $user = $request->getUser();
        $isSupported = $request->cookies->has('hanko') && is_null($user);

        if (!$isSupported) {
            $this->logger->debug(sprintf(
                'Authenticator %s does not support requests for %s',
                self::class,
                $request->getPathInfo()
            ));
        } else {
            $this->logger->debug(sprintf(
                'Authenticator %s does support requests for %s',
                self::class,
                $request->getPathInfo()
            ));
        }

        return $isSupported;
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->httpUtils->generateUri($request, 'security_login');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $this->logger->debug(sprintf(
            'Authenticator %s::authenticate called on %s',
            self::class,
            $request->getPathInfo()
        ));

        $jwt = $this->getCredentials($request);
        $parser = new Parser(new JoseEncoder());
        $token = $parser->parse($jwt);

        $keyResponse = $this->client->request(
            'GET',
            sprintf('%s/.well-known/jwks.json', $this->hankoApiUrl)
        );

        if ($keyResponse->getStatusCode() !== 200) {
            $this->logger->debug(sprintf(
                'Could not fetch JWKS from %s',
                $this->hankoApiUrl
            ));
            throw new \Exception('e');
        }

        $keySetFactory = new KeySetFactory();
        $keySet = $keySetFactory->createFromJSON($keyResponse->getContent());

        $validator = new Validator();
        $keyConverter = new KeyConverter();
        $kid = $token->headers()->get('kid');
        if (is_null($kid)) {
            $this->logger->debug(sprintf(
                'KID missing for token %s',
                $jwt
            ));
            throw new InvalidTokenException();
        }

        $key = $keySet->getKeyById($kid);

        if (is_null($key)) {
            $this->logger->debug(sprintf(
                'Key (%s) missing from %s JWKS',
                $kid,
                $this->hankoApiUrl
            ));
            throw new InvalidTokenException();
        }

        $alg = $token->headers()->get('alg');
        $signer = $this->getSignerForAlgorithm($alg);

        $key = InMemory::plainText($keyConverter->keyToPem($key));

        $validationResult = $validator->validate(
            $token,
            new SignedWith($signer, $key),
            new LooseValidAt(
                SystemClock::fromSystemTimezone()
            )
        );

        if (!$validationResult) {
            $this->logger->debug(sprintf(
                'JWT invalid with %s (alg: %s; kid: %s)',
                $this->hankoApiUrl,
                $alg,
                $kid
            ));
            throw new InvalidTokenException();
        }

        $claims = $token->claims()->all();
        $this->logger->debug(sprintf(
            'Token claims: %s',
            json_encode($claims)
        ));

        if (!isset($claims['sub'])) {
            $this->logger->debug('Invalid payload');
            throw new InvalidPayloadException('sub');
        }

        $passport = new SelfValidatingPassport(
            new UserBadge($claims['sub'])
        );

        $passport->setAttribute('payload', $claims);
        $passport->setAttribute('token', $jwt);

        return $passport;
    }

    private function getCredentials(Request $request): string
    {
        $token = $request->cookies->get('hanko', false);

        if (!is_string($token)) {
            throw new BadRequestHttpException(
                sprintf('The key "%s" must be a string, "%s" given.', 'hanko', gettype($token))
            );
        }

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    private function getSignerForAlgorithm(string $signatureAlgorithm): Signer
    {
        $signerMap = [
            'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
            'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
            'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
            'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
            'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
            'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
            'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
            'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
        ];

        if (!isset($signerMap[$signatureAlgorithm])) {
            throw new \InvalidArgumentException(
                sprintf(
                    'The algorithm "%s" is not supported by %s',
                    $signatureAlgorithm,
                    self::class
                )
            );
        }

        $signerClass = $signerMap[$signatureAlgorithm];

        if (is_subclass_of($signerClass, \Lcobucci\JWT\Signer\Ecdsa::class) && method_exists($signerClass, 'create')) {
            return $signerClass::create();
        }

        return new $signerClass();
    }
}
