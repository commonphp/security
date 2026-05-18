<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Fixtures;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Permission;

final readonly class CallbackPolicy implements PolicyInterface
{
    /**
     * @param callable(SecurityContextInterface, Permission, mixed): (AuthorizationResult|AccessDecision|bool) $decider
     * @param (callable(Permission, mixed): bool)|null $supports
     */
    public function __construct(
        private string $name,
        private Permission|string $permission,
        private mixed $decider,
        private mixed $supports = null,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function supports(Permission|string $permission, mixed $resource = null): bool
    {
        if ($this->supports !== null) {
            return ($this->supports)(Permission::from($permission), $resource);
        }

        return Permission::from($this->permission)->equals(Permission::from($permission));
    }

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult|AccessDecision|bool {
        return ($this->decider)($context, Permission::from($permission), $resource);
    }
}
