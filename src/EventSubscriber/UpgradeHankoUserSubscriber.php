<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Security\HankoUser;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class UpgradeHankoUserSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly Security $security
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $registerUrl = $this->urlGenerator->generate('security_register');

        if (!$event->isMainRequest()) {
            return;
        }

        if (str_ends_with($request->getRequestUri(), $registerUrl)) {
            return;
        }

        $user = $this->security->getUser();

        if ($user instanceof HankoUser) {
            $response = new RedirectResponse($registerUrl);
            $event->setResponse($response);
        }
    }
}
