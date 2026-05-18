<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Exceptions\AuthorizationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AccessDecisionTest extends TestCase
{
    #[DataProvider('decisionProvider')]
    public function testItNormalizesDecisions(mixed $value, AccessDecision $expected): void
    {
        self::assertSame($expected, AccessDecision::normalize($value));
    }

    public function testItExposesDecisionState(): void
    {
        self::assertTrue(AccessDecision::Allow->isGranted());
        self::assertFalse(AccessDecision::Allow->isDenied());
        self::assertFalse(AccessDecision::Allow->isAbstain());
        self::assertTrue(AccessDecision::Deny->isDenied());
        self::assertFalse(AccessDecision::Deny->isGranted());
        self::assertFalse(AccessDecision::Deny->isAbstain());
        self::assertTrue(AccessDecision::Abstain->isAbstain());
        self::assertFalse(AccessDecision::Abstain->isGranted());
        self::assertFalse(AccessDecision::Abstain->isDenied());
        self::assertSame(AccessDecision::Allow, AccessDecision::fromBool(true));
        self::assertSame(AccessDecision::Deny, AccessDecision::fromBool(false));
        self::assertSame('allow', AccessDecision::Allow->value);
        self::assertSame('deny', AccessDecision::Deny->value);
        self::assertSame('abstain', AccessDecision::Abstain->value);
    }

    public function testItRejectsUnknownDecisions(): void
    {
        $this->expectException(AuthorizationException::class);

        AccessDecision::normalize('maybe');
    }

    public static function decisionProvider(): iterable
    {
        yield 'enum' => [AccessDecision::Allow, AccessDecision::Allow];
        yield 'true' => [true, AccessDecision::Allow];
        yield 'false' => [false, AccessDecision::Deny];
        yield 'grant string' => [' granted ', AccessDecision::Allow];
        yield 'yes string' => ['YES', AccessDecision::Allow];
        yield 'true string' => ['true', AccessDecision::Allow];
        yield 'deny string' => ['REJECTED', AccessDecision::Deny];
        yield 'no string' => ['no', AccessDecision::Deny];
        yield 'false string' => ['false', AccessDecision::Deny];
        yield 'abstain string' => ['neutral', AccessDecision::Abstain];
        yield 'skip string' => ['skip', AccessDecision::Abstain];
    }
}
