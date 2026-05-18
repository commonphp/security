<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

class AuthorizationException extends SecurityException
{
    public static function invalidPermission(string $permission, ?string $reason = null): self
    {
        return new self(
            'Invalid permission "' . ($permission === '' ? '<empty>' : $permission) . '".'
            . ($reason === null ? '' : ' ' . $reason),
        );
    }

    public static function invalidRole(string $role, ?string $reason = null): self
    {
        return new self(
            'Invalid role "' . ($role === '' ? '<empty>' : $role) . '".'
            . ($reason === null ? '' : ' ' . $reason),
        );
    }

    public static function invalidPolicyName(string $name): self
    {
        return new self('Invalid policy name "' . ($name === '' ? '<empty>' : $name) . '".');
    }

    public static function invalidDecision(string $decision): self
    {
        return new self('Invalid access decision "' . $decision . '".');
    }

    public static function invalidPolicyResult(string $policyName, mixed $result): self
    {
        return new self(
            'Policy "' . $policyName . '" returned unsupported result type ' . get_debug_type($result) . '.',
        );
    }
}
