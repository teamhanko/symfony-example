<?php

declare(strict_types=1);

namespace App\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class InvalidTokenException extends AuthenticationException
{
    public function getMessageKey(): string
    {
        return 'Invalid JWT Token';
    }
}
