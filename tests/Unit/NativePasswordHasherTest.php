<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\Contracts\PasswordHasherInterface;
use CommonPHP\Security\Exceptions\PasswordHashException;
use CommonPHP\Security\NativePasswordHasher;
use PHPUnit\Framework\TestCase;

final class NativePasswordHasherTest extends TestCase
{
    public function testItHashesVerifiesAndChecksRehashNeeds(): void
    {
        $defaultHasher = new NativePasswordHasher();
        $hasher = new NativePasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]);
        $hash = $hasher->hash('correct-password');

        self::assertInstanceOf(PasswordHasherInterface::class, $hasher);
        self::assertNotSame('', $defaultHasher->hash('password'));
        self::assertTrue($hasher->verify('correct-password', $hash));
        self::assertFalse($hasher->verify('wrong-password', $hash));
        self::assertFalse($hasher->verify('correct-password', ''));
        self::assertFalse($hasher->verify('correct-password', 'not-a-password-hash'));
        self::assertFalse($hasher->needsRehash($hash));
        self::assertTrue((new NativePasswordHasher(PASSWORD_BCRYPT, ['cost' => 5]))->needsRehash($hash));
        self::assertSame(PASSWORD_BCRYPT, $hasher->algorithm());
        self::assertSame(['cost' => 4], $hasher->options());
    }

    public function testInvalidAlgorithmsAreWrapped(): void
    {
        $hasher = new NativePasswordHasher('not-a-real-algorithm');

        $this->expectException(PasswordHashException::class);

        $hasher->hash('password');
    }

    public function testUnknownAlgorithmsUseNativeRehashBehavior(): void
    {
        $hasher = new NativePasswordHasher('not-a-real-algorithm');

        self::assertFalse($hasher->needsRehash('stored-hash'));
    }
}
