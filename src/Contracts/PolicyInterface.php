<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Permission;

interface PolicyInterface
{
    public function name(): string;

    public function supports(Permission|string $permission, mixed $resource = null): bool;

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult|AccessDecision|bool;
}
