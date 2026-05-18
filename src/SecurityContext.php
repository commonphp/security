<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Contracts\SecurityContextInterface;

final class SecurityContext implements SecurityContextInterface
{
    private mixed $identity;

    private bool $authenticated;

    /**
     * @var array<string, Role>
     */
    private array $roles = [];

    /**
     * @var array<string, Permission>
     */
    private array $permissions = [];

    /**
     * @param iterable<Role|string> $roles
     * @param iterable<Permission|string> $permissions
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        mixed $identity = null,
        iterable $roles = [],
        iterable $permissions = [],
        private array $attributes = [],
        ?bool $authenticated = null,
    ) {
        $this->identity = $identity;
        $this->authenticated = $authenticated ?? $identity !== null;

        foreach ($roles as $role) {
            $this->addRole($role);
        }

        foreach ($permissions as $permission) {
            $this->grant($permission);
        }
    }

    public static function guest(): self
    {
        return new self(authenticated: false);
    }

    /**
     * @param iterable<Role|string> $roles
     * @param iterable<Permission|string> $permissions
     * @param array<string, mixed> $attributes
     */
    public static function forIdentity(
        mixed $identity,
        iterable $roles = [],
        iterable $permissions = [],
        array $attributes = [],
    ): self {
        return new self($identity, $roles, $permissions, $attributes, true);
    }

    public function identity(): mixed
    {
        return $this->identity;
    }

    public function user(): mixed
    {
        return $this->identity();
    }

    public function authenticate(mixed $identity): static
    {
        $this->identity = $identity;
        $this->authenticated = true;

        return $this;
    }

    public function logout(): static
    {
        $this->identity = null;
        $this->authenticated = false;
        $this->roles = [];
        $this->permissions = [];

        return $this;
    }

    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    public function isGuest(): bool
    {
        return !$this->authenticated;
    }

    public function addRole(Role|string $role): static
    {
        $role = Role::from($role);
        $this->roles[$role->name()] = clone $role;

        return $this;
    }

    public function removeRole(Role|string $role): static
    {
        unset($this->roles[Role::from($role)->name()]);

        return $this;
    }

    public function hasRole(Role|string $role): bool
    {
        return isset($this->roles[Role::from($role)->name()]);
    }

    /**
     * @return list<Role>
     */
    public function roles(): array
    {
        return array_map(static fn (Role $role): Role => clone $role, array_values($this->roles));
    }

    /**
     * @return list<string>
     */
    public function roleNames(): array
    {
        return array_keys($this->roles);
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
        $permission = Permission::from($permission);

        if (isset($this->permissions[$permission->value()])) {
            return true;
        }

        foreach ($this->roles as $role) {
            if ($role->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<Permission>
     */
    public function permissions(): array
    {
        $permissions = $this->permissions;

        foreach ($this->roles as $role) {
            foreach ($role->permissions() as $permission) {
                $permissions[$permission->value()] = $permission;
            }
        }

        return array_values($permissions);
    }

    /**
     * @return list<Permission>
     */
    public function directPermissions(): array
    {
        return array_values($this->permissions);
    }

    public function setAttribute(string $key, mixed $value): static
    {
        $this->attributes[$key] = $value;

        return $this;
    }

    public function removeAttribute(string $key): static
    {
        unset($this->attributes[$key]);

        return $this;
    }

    public function attribute(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->attributes) ? $this->attributes[$key] : $default;
    }

    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array
    {
        return $this->attributes;
    }
}
