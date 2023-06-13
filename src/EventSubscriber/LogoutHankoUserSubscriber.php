<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutHankoUserSubscriber implements EventSubscriberInterface
{

    public function __construct(
        private readonly UrlGeneratorInterface $urlGenerator
    )
    {}

    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => 'onLogout'
        ];
    }

    public function onLogout(LogoutEvent $event): void
    {
        $response = new RedirectResponse($this->urlGenerator->generate('blog_index'));
        $response->headers->clearCookie('hanko', '/', null);

        $event->setResponse($response);
    }
}
