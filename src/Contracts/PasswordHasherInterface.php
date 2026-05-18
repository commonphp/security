<?php

declare(strict_types=1);

namespace CommonPHP\Security\Contracts;

interface PasswordHasherInterface
{
    public function hash(string $plainPassword): string;

    public function verify(string $plainPassword, string $hash): bool;

    public function needsRehash(string $hash): bool;
}
