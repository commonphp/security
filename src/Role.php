<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use ArrayIterator;
use CommonPHP\Security\Exceptions\AuthorizationException;
use Countable;
use IteratorAggregate;
use Stringable;
use Traversable;

/**
 * @implements IteratorAggregate<string, Permission>
 */
final class Role implements Countable, IteratorAggregate, Stringable
{
    public const int MAX_LENGTH = 96;

    private string $name;

    /**
     * @var array<string, Permission>
     */
    private array $permissions = [];

    /**
     * @param iterable<Permission|string> $permissions
     */
    public function __construct(string|Stringable $name, iterable $permissions = [])
    {
        $this->name = self::normalize((string) $name);

        foreach ($permissions as $permission) {
            $this->grant($permission);
        }
    }

    public static function from(string|Stringable|self $role): self
    {
        return $role instanceof self ? $role : new self($role);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function value(): string
    {
        return $this->name;
    }

    public function grant(Permission|string $permission, Permission|string ...$permissions): static
    {
        foreach ([$permission, ...$permissions] as $entry) {
            $normalized = Permission::from($entry);
            $this->permissions[$normalized->value()] = $normalized;
        }

        return $this;
    }

    public function revoke(Permission|string $permission): static
    {
        unset($this->permissions[Permission::from($permission)->value()]);

        return $this;
    }

    public function hasPermission(Permission|string $permission): bool
    {
        return isset($this->permissions[Permission::from($permission)->value()]);
    }

    /**
     * @return list<Permission>
     */
    public function permissions(): array
    {
        return array_values($this->permissions);
    }

    /**
     * @return list<string>
     */
    public function permissionNames(): array
    {
        return array_keys($this->permissions);
    }

    public function clearPermissions(): static
    {
        $this->permissions = [];

        return $this;
    }

    public function equals(string|Stringable|self $role): bool
    {
        return $this->name === self::from($role)->name();
    }

    public function count(): int
    {
        return count($this->permissions);
    }

    /**
     * @return Traversable<string, Permission>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->permissions);
    }

    public function __toString(): string
    {
        return $this->name;
    }

    private static function normalize(string $name): string
    {
        $name = trim($name);

        if ($name === '') {
            throw AuthorizationException::invalidRole($name, 'Roles cannot be empty.');
        }

        if (strlen($name) > self::MAX_LENGTH) {
            throw AuthorizationException::invalidRole(
                $name,
                'Roles cannot be longer than ' . self::MAX_LENGTH . ' bytes.',
            );
        }

        if (preg_match('/^[A-Za-z0-9_.:-]+$/', $name) !== 1) {
            throw AuthorizationException::invalidRole(
                $name,
                'Use letters, numbers, dots, underscores, colons, or hyphens.',
            );
        }

        return $name;
    }
}
