<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class HankoAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{

    public function __construct(
        private readonly UrlGeneratorInterface $router,
        private readonly Security $security
    )
    {}

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $user = $this->security->getUser();

        if ($user instanceof HankoUser) {
            return new RedirectResponse($this->router->generate('security_register'));
        }

        return new RedirectResponse($this->router->generate('security_login'));
    }
}
