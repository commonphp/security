<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

class PolicyNotFoundException extends SecurityException
{
    public static function forName(string $name): self
    {
        return new self('No security policy is registered with name "' . $name . '".');
    }
}
