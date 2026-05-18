<?php

declare(strict_types=1);

namespace CommonPHP\Security\Exceptions;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Permission;

class AccessDeniedException extends AuthorizationException
{
    public static function forPermission(Permission|string $permission, ?string $reason = null): self
    {
        $permission = Permission::from($permission);

        return new self($reason ?? 'Access denied for permission "' . $permission->value() . '".');
    }

    public static function forResult(AuthorizationResult $result): self
    {
        $permission = $result->permission()?->value();
        $message = $result->reason()
            ?? ($permission === null ? 'Access denied.' : 'Access denied for permission "' . $permission . '".');

        return new self($message);
    }
}
