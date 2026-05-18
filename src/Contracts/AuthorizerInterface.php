<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Permission;

interface AuthorizerInterface
{
    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult;

    public function can(SecurityContextInterface $context, Permission|string $permission, mixed $resource = null): bool;

    public function cannot(SecurityContextInterface $context, Permission|string $permission, mixed $resource = null): bool;

    public function authorize(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult;
}
