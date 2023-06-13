<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class HankoUserProvider implements UserProviderInterface
{

    public function refreshUser(UserInterface $user): UserInterface
    {
        // no need to refresh a user, as it doesn't hold any additional data
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return HankoUser::class === $class || is_subclass_of($class, HankoUser::class);
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        return new HankoUser($identifier);
    }
}
