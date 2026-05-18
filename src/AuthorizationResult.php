<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Exceptions\AccessDeniedException;

final readonly class AuthorizationResult
{
    private AccessDecision $decision;

    private ?string $reason;

    private ?Permission $permission;

    private mixed $resource;

    private ?string $policy;

    public function __construct(
        AccessDecision $decision,
        ?string $reason = null,
        Permission|string|null $permission = null,
        mixed $resource = null,
        ?string $policy = null,
    ) {
        $this->decision = $decision;
        $this->reason = $reason;
        $this->permission = $permission === null ? null : Permission::from($permission);
        $this->resource = $resource;
        $this->policy = $policy;
    }

    public static function allow(
        ?string $reason = null,
        Permission|string|null $permission = null,
        mixed $resource = null,
        ?string $policy = null,
    ): self {
        return new self(AccessDecision::Allow, $reason, $permission, $resource, $policy);
    }

    public static function deny(
        ?string $reason = null,
        Permission|string|null $permission = null,
        mixed $resource = null,
        ?string $policy = null,
    ): self {
        return new self(AccessDecision::Deny, $reason, $permission, $resource, $policy);
    }

    public static function abstain(
        ?string $reason = null,
        Permission|string|null $permission = null,
        mixed $resource = null,
        ?string $policy = null,
    ): self {
        return new self(AccessDecision::Abstain, $reason, $permission, $resource, $policy);
    }

    public static function from(
        self|AccessDecision|bool $result,
        Permission|string|null $permission = null,
        mixed $resource = null,
        ?string $policy = null,
    ): self {
        if ($result instanceof self) {
            return new self(
                $result->decision,
                $result->reason,
                $result->permission ?? $permission,
                $result->resource ?? $resource,
                $result->policy ?? $policy,
            );
        }

        return new self(AccessDecision::normalize($result), permission: $permission, resource: $resource, policy: $policy);
    }

    public function decision(): AccessDecision
    {
        return $this->decision;
    }

    public function reason(): ?string
    {
        return $this->reason;
    }

    public function permission(): ?Permission
    {
        return $this->permission;
    }

    public function resource(): mixed
    {
        return $this->resource;
    }

    public function policy(): ?string
    {
        return $this->policy;
    }

    public function isGranted(): bool
    {
        return $this->decision->isGranted();
    }

    public function isDenied(): bool
    {
        return $this->decision->isDenied();
    }

    public function isAbstain(): bool
    {
        return $this->decision->isAbstain();
    }

    public function withPolicy(string $policy): self
    {
        return new self($this->decision, $this->reason, $this->permission, $this->resource, $policy);
    }

    public function throwIfDenied(?string $message = null): void
    {
        if (!$this->isGranted()) {
            throw $message === null
                ? AccessDeniedException::forResult($this)
                : new AccessDeniedException($message);
        }
    }
}
