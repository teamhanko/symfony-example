<?php

declare(strict_types=1);

namespace App\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class InvalidPayloadException extends AuthenticationException
{
}
