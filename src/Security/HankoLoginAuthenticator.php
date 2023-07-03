<?php

declare(strict_types=1);

namespace App\Security;

use App\Exception\InvalidPayloadException;
use App\Exception\InvalidTokenException;
use App\Exception\KeySetFetchFailedException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Psr\Log\LoggerInterface;
use Strobotti\JWK\KeyConverter;
use Strobotti\JWK\KeySetFactory;
use Symfony\Component\HttpClient\CachingHttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\HttpCache\StoreInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class HankoLoginAuthenticator extends AbstractAuthenticator
{

    private readonly HttpClientInterface $client;

    public function __construct(
        private readonly LoggerInterface $logger,
        HttpClientInterface $client,
        StoreInterface $httpCacheStore,
        private readonly string $hankoApiUrl
    ) {
        $this->client = new CachingHttpClient($client, $httpCacheStore);
    }

    public function supports(Request $request): bool
    {
        $isSupported = $request->cookies->has('hanko')
            && !empty($request->cookies->get('hanko'));

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

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $this->logger->debug(sprintf(
            'Authenticator %s::authenticate called on %s',
            self::class,
            $request->getPathInfo()
        ));

        $jwt = $this->getCredentials($request);
        $parser = new Parser(new JoseEncoder());

        assert(!empty($jwt), 'JWT string value should not be empty');
        $token = $parser->parse($jwt);

        if (!$token instanceof UnencryptedToken) {
            $this->logger->debug('Token not readable');
            throw new InvalidTokenException();
        }

        $keySetFactory = new KeySetFactory();

        try {
            $keyResponse = $this->client->request(
                'GET',
                sprintf('%s/.well-known/jwks.json', $this->hankoApiUrl)
            );

            if ($keyResponse->getStatusCode() !== 200) {
                throw new KeySetFetchFailedException();
            }

            $keySet = $keySetFactory->createFromJSON($keyResponse->getContent());
        } catch (KeySetFetchFailedException|HttpExceptionInterface|TransportExceptionInterface $e) {
            $this->logger->debug(sprintf(
                'Could not fetch JWKS from %s',
                $this->hankoApiUrl
            ));

            throw new KeySetFetchFailedException("", 0, (!$e instanceof KeySetFetchFailedException) ? $e : null);
        }

        $validator = new Validator();
        $keyConverter = new KeyConverter();
        $kid = $token->headers()->get('kid');
        if (!is_string($kid)) {
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
        if (!is_string($alg)) {
            $this->logger->debug(sprintf(
                'ALG missing for token %s',
                $jwt
            ));
            throw new InvalidTokenException();
        }
        $signer = $this->getSignerForAlgorithm($alg);

        $pemKey = $keyConverter->keyToPem($key);

        assert(!empty($pemKey), 'Converted JWK should not be empty');
        $key = InMemory::plainText($pemKey);

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
        $this->logger->debug(
            sprintf('Token claims: %s', implode(', ', array_keys($claims))),
            $claims
        );

        if (!isset($claims['sub']) || !is_string($claims['sub'])) {
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
        $token = $request->cookies->get('hanko');

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
