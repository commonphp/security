<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;

interface SecurityContextInterface
{
    public function identity(): mixed;

    public function user(): mixed;

    public function isAuthenticated(): bool;

    public function isGuest(): bool;

    /**
     * @return list<Role>
     */
    public function roles(): array;

    /**
     * @return list<Permission>
     */
    public function permissions(): array;

    /**
     * @return list<Permission>
     */
    public function directPermissions(): array;

    public function hasRole(Role|string $role): bool;

    public function hasPermission(Permission|string $permission): bool;

    public function attribute(string $key, mixed $default = null): mixed;

    public function hasAttribute(string $key): bool;

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array;
}
