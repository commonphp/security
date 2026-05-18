<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

use RuntimeException;

class SecurityException extends RuntimeException
{
    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
