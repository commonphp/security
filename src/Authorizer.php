<?php

declare(strict_types=1);

namespace CommonPHP\Security;

use CommonPHP\Security\Contracts\AuthorizerInterface;
use CommonPHP\Security\Contracts\PolicyInterface;
use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Exceptions\AuthorizationException;

final class Authorizer implements AuthorizerInterface
{
    public function __construct(
        private readonly PolicyRegistry $policies = new PolicyRegistry(),
    ) {
    }

    /**
     * @param iterable<PolicyInterface> $policies
     */
    public static function withPolicies(iterable $policies): self
    {
        return new self(new PolicyRegistry($policies));
    }

    public function policies(): PolicyRegistry
    {
        return $this->policies;
    }

    public function decide(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult {
        $permission = Permission::from($permission);
        $allow = null;
        $matchedPolicy = false;

        foreach ($this->policies->matching($permission, $resource) as $policy) {
            $matchedPolicy = true;
            $result = $this->normalizePolicyResult($policy, $context, $permission, $resource);

            if ($result->isDenied()) {
                return $result;
            }

            if ($allow === null && $result->isGranted()) {
                $allow = $result;
            }
        }

        if ($allow !== null) {
            return $allow;
        }

        if ($context->hasPermission($permission)) {
            return AuthorizationResult::allow(
                'Permission "' . $permission->value() . '" is granted by the security context.',
                $permission,
                $resource,
            );
        }

        $reason = $matchedPolicy
            ? 'No security policy granted permission "' . $permission->value() . '".'
            : 'Permission "' . $permission->value() . '" is not granted.';

        return AuthorizationResult::deny($reason, $permission, $resource);
    }

    public function can(SecurityContextInterface $context, Permission|string $permission, mixed $resource = null): bool
    {
        return $this->decide($context, $permission, $resource)->isGranted();
    }

    public function cannot(SecurityContextInterface $context, Permission|string $permission, mixed $resource = null): bool
    {
        return !$this->can($context, $permission, $resource);
    }

    public function authorize(
        SecurityContextInterface $context,
        Permission|string $permission,
        mixed $resource = null,
    ): AuthorizationResult {
        $result = $this->decide($context, $permission, $resource);
        $result->throwIfDenied();

        return $result;
    }

    private function normalizePolicyResult(
        PolicyInterface $policy,
        SecurityContextInterface $context,
        Permission $permission,
        mixed $resource,
    ): AuthorizationResult {
        $result = $policy->decide($context, $permission, $resource);

        if (
            !$result instanceof AuthorizationResult
            && !$result instanceof AccessDecision
            && !is_bool($result)
        ) {
            throw AuthorizationException::invalidPolicyResult($policy->name(), $result);
        }

        return AuthorizationResult::from($result, $permission, $resource, $policy->name());
    }
}
