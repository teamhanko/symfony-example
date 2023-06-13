<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class HankoUser implements UserInterface
{

    private string $hankoSubjectId;

    public function __construct(string $hankoSubscriberId)
    {
        $this->hankoSubjectId = $hankoSubscriberId;
    }

    public function getRoles(): array
    {
        return [];
    }

    public function eraseCredentials(): void
    {
        // do nothing as no credentials are managed here
    }

    public function getUserIdentifier(): string
    {
        return $this->hankoSubjectId;
    }
}
