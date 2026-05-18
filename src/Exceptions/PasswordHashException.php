<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

use Throwable;

class PasswordHashException extends SecurityException
{
    public static function forHashing(?Throwable $previous = null): self
    {
        return new self('Password could not be hashed.', previous: $previous);
    }

    public static function forRehashCheck(?Throwable $previous = null): self
    {
        return new self('Password hash rehash requirements could not be checked.', previous: $previous);
    }
}
