<?php

declare(strict_types=1);

namespace CommonPHP\Security\Enums;

use CommonPHP\Security\Exceptions\AuthorizationException;

enum AccessDecision: string
{
    case Allow = 'allow';
    case Deny = 'deny';
    case Abstain = 'abstain';

    public static function fromBool(bool $allowed): self
    {
        return $allowed ? self::Allow : self::Deny;
    }

    public static function normalize(self|bool|string $decision): self
    {
        if ($decision instanceof self) {
            return $decision;
        }

        if (is_bool($decision)) {
            return self::fromBool($decision);
        }

        return match (strtolower(trim($decision))) {
            'allow', 'allowed', 'grant', 'granted', 'yes', 'true' => self::Allow,
            'deny', 'denied', 'reject', 'rejected', 'no', 'false' => self::Deny,
            'abstain', 'neutral', 'skip' => self::Abstain,
            default => throw AuthorizationException::invalidDecision($decision),
        };
    }

    public function isGranted(): bool
    {
        return $this === self::Allow;
    }

    public function isDenied(): bool
    {
        return $this === self::Deny;
    }

    public function isAbstain(): bool
    {
        return $this === self::Abstain;
    }
}
