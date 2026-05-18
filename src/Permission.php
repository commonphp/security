<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Exceptions\AuthorizationException;
use Stringable;

final readonly class Permission implements Stringable
{
    public const int MAX_LENGTH = 128;

    private string $value;

    public function __construct(string|Stringable $value)
    {
        $this->value = self::normalize((string) $value);
    }

    public static function from(string|Stringable|self $permission): self
    {
        return $permission instanceof self ? $permission : new self($permission);
    }

    public function value(): string
    {
        return $this->value;
    }

    public function name(): string
    {
        return $this->value;
    }

    public function equals(string|Stringable|self $permission): bool
    {
        return $this->value === self::from($permission)->value();
    }

    public function __toString(): string
    {
        return $this->value;
    }

    private static function normalize(string $value): string
    {
        $value = trim($value);

        if ($value === '') {
            throw AuthorizationException::invalidPermission($value, 'Permissions cannot be empty.');
        }

        if (strlen($value) > self::MAX_LENGTH) {
            throw AuthorizationException::invalidPermission(
                $value,
                'Permissions cannot be longer than ' . self::MAX_LENGTH . ' bytes.',
            );
        }

        if (preg_match('/^[A-Za-z0-9_.:-]+$/', $value) !== 1) {
            throw AuthorizationException::invalidPermission(
                $value,
                'Use letters, numbers, dots, underscores, colons, or hyphens.',
            );
        }

        return $value;
    }
}
