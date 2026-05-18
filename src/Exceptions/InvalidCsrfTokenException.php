<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

use Throwable;

class InvalidCsrfTokenException extends SecurityException
{
    public static function invalidId(string $id): self
    {
        return new self('Invalid CSRF token id "' . ($id === '' ? '<empty>' : $id) . '".');
    }

    public static function invalidValue(): self
    {
        return new self('Invalid CSRF token value.');
    }

    public static function missing(string $id): self
    {
        return new self('CSRF token "' . $id . '" was not found.');
    }

    public static function mismatch(string $id): self
    {
        return new self('CSRF token "' . $id . '" does not match.');
    }

    public static function expired(string $id): self
    {
        return new self('CSRF token "' . $id . '" has expired.');
    }

    public static function malformed(string $id): self
    {
        return new self('CSRF token "' . $id . '" contains invalid stored data.');
    }

    public static function invalidGeneratorConfig(string $reason): self
    {
        return new self('Invalid CSRF token generator configuration. ' . $reason);
    }

    public static function generationFailed(Throwable $previous): self
    {
        return new self('Unable to generate a CSRF token.', previous: $previous);
    }
}
