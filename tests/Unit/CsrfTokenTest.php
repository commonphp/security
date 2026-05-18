<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\Contracts\CsrfTokenManagerInterface;
use CommonPHP\Security\Contracts\CsrfTokenStorageInterface;
use CommonPHP\Security\CsrfToken;
use CommonPHP\Security\CsrfTokenManager;
use CommonPHP\Security\Exceptions\InvalidCsrfTokenException;
use CommonPHP\Security\SessionCsrfTokenStorage;
use CommonPHP\Security\Tests\Fixtures\ArrayBackedSession;
use CommonPHP\Security\Tests\Fixtures\MemoryCsrfTokenStorage;
use CommonPHP\Session\SessionBag;
use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class CsrfTokenTest extends TestCase
{
    public function testTokenSerializesMatchesAndExpires(): void
    {
        $createdAt = new DateTimeImmutable('2026-01-01 00:00:00');
        $token = new CsrfToken(' login ', 'abc123', $createdAt);
        $payload = $token->toArray();
        $hydrated = CsrfToken::fromArray($payload);

        self::assertSame('login', $token->id());
        self::assertSame('abc123', $token->value());
        self::assertSame('abc123', (string) $token);
        self::assertEquals($createdAt, $token->createdAt());
        self::assertTrue($token->matches('abc123'));
        self::assertTrue($token->matches(new CsrfToken('login', 'abc123')));
        self::assertFalse($token->matches('other'));
        self::assertSame($token->value(), $hydrated->value());
        self::assertTrue($token->isExpired(new DateInterval('PT1S'), new DateTimeImmutable('2026-01-01 00:00:02')));
        self::assertFalse($token->isExpired(new DateInterval('PT1S'), new DateTimeImmutable('2026-01-01 00:00:00')));
        self::assertSame('profile', CsrfToken::create(' profile ', 'value')->id());
        self::assertSame(str_repeat('a', CsrfToken::MAX_ID_LENGTH), CsrfToken::normalizeId(str_repeat('a', CsrfToken::MAX_ID_LENGTH)));
    }

    public function testTokenRejectsInvalidInput(): void
    {
        foreach (['bad id', '', str_repeat('a', CsrfToken::MAX_ID_LENGTH + 1)] as $id) {
            try {
                new CsrfToken($id, 'value');
                self::fail('Expected invalid CSRF id exception.');
            } catch (InvalidCsrfTokenException $exception) {
                self::assertStringContainsString('Invalid CSRF token id', $exception->getMessage());
            }
        }

        foreach (['', "line\nbreak"] as $value) {
            try {
                new CsrfToken('valid-id', $value);
                self::fail('Expected invalid CSRF value exception.');
            } catch (InvalidCsrfTokenException $exception) {
                self::assertStringContainsString('Invalid CSRF token value', $exception->getMessage());
            }
        }
    }

    public function testTokenRejectsMalformedArrayPayloads(): void
    {
        foreach (
            [
                [],
                ['id' => 'token'],
                ['id' => 'token', 'value' => ['not-string']],
                ['id' => 'token', 'value' => 'value', 'createdAt' => []],
                ['id' => 'token', 'value' => 'value', 'createdAt' => 'not-a-real-date'],
            ] as $payload
        ) {
            try {
                CsrfToken::fromArray($payload);
                self::fail('Expected malformed CSRF token exception.');
            } catch (InvalidCsrfTokenException $exception) {
                self::assertStringContainsString('contains invalid stored data', $exception->getMessage());
            }
        }
    }

    public function testManagerGeneratesCachesRefreshesValidatesAndConsumesTokens(): void
    {
        $storage = new MemoryCsrfTokenStorage();
        $manager = new CsrfTokenManager($storage, 16);
        $token = $manager->getToken('login');

        self::assertInstanceOf(CsrfTokenManagerInterface::class, $manager);
        self::assertSame('_token', CsrfTokenManager::DEFAULT_TOKEN_ID);
        self::assertSame('_token', CsrfTokenManagerInterface::DEFAULT_TOKEN_ID);
        self::assertSame($token, $manager->getToken('login'));
        self::assertTrue($manager->hasToken('login'));
        self::assertTrue($manager->isTokenValid('login', $token->value()));
        self::assertSame($token, $manager->validateToken('login', $token->value()));
        self::assertFalse($manager->isTokenValid('login', 'bad-token'));

        $refreshed = $manager->refreshToken('login');
        self::assertNotSame($token->value(), $refreshed->value());

        self::assertTrue($manager->isTokenValid('login', $refreshed->value(), consume: true));
        self::assertFalse($manager->hasToken('login'));
    }

    public function testManagerRefreshesExpiredTokensAndHandlesValidationFailures(): void
    {
        $expired = new CsrfToken('login', 'expired-value', new DateTimeImmutable('2026-01-01 00:00:00'));
        $storage = new MemoryCsrfTokenStorage([$expired]);
        $manager = new CsrfTokenManager($storage, 16, new DateInterval('PT1S'));

        $refreshed = $manager->getToken('login');

        self::assertNotSame('expired-value', $refreshed->value());
        self::assertTrue($storage->has('login'));

        try {
            $manager->validateToken('missing', 'value');
            self::fail('Expected missing CSRF token exception.');
        } catch (InvalidCsrfTokenException $exception) {
            self::assertStringContainsString('was not found', $exception->getMessage());
        }

        try {
            $manager->validateToken('login', 'wrong-value');
            self::fail('Expected mismatched CSRF token exception.');
        } catch (InvalidCsrfTokenException $exception) {
            self::assertStringContainsString('does not match', $exception->getMessage());
        }

        $storage->put($expired);

        try {
            $manager->validateToken('login', 'expired-value');
            self::fail('Expected expired CSRF token exception.');
        } catch (InvalidCsrfTokenException $exception) {
            self::assertStringContainsString('has expired', $exception->getMessage());
        }

        self::assertFalse($storage->has('login'));
        self::assertFalse($manager->isTokenValid('bad id', 'value'));
    }

    public function testManagerRemovesExpiredTokensAndRejectsWeakEntropy(): void
    {
        $storage = new MemoryCsrfTokenStorage([
            new CsrfToken('expired', 'old-token', new DateTimeImmutable('2026-01-01 00:00:00')),
        ]);
        $manager = new CsrfTokenManager($storage, 16, new DateInterval('PT1S'));

        self::assertFalse($manager->hasToken('expired'));
        self::assertFalse($storage->has('expired'));
        self::assertSame($manager, $manager->removeToken('missing'));

        $this->expectException(InvalidCsrfTokenException::class);

        new CsrfTokenManager(new MemoryCsrfTokenStorage(), 8);
    }

    public function testSessionStorageUsesBagsAndHydratesStoredTokens(): void
    {
        $bag = SessionBag::create();
        $storage = new SessionCsrfTokenStorage($bag);
        $token = new CsrfToken('checkout', 'token-value', new DateTimeImmutable('2026-01-01 00:00:00'));

        self::assertInstanceOf(CsrfTokenStorageInterface::class, $storage);
        self::assertNull($storage->get('checkout'));
        self::assertSame($storage, $storage->put($token));
        self::assertTrue($storage->has('checkout'));
        self::assertEquals($token, $storage->get('checkout'));
        self::assertSame(['checkout'], array_keys($storage->all()));

        $storage->remove('checkout');
        self::assertFalse($storage->has('checkout'));

        $bag->set('legacy', 'legacy-value');
        self::assertSame('legacy-value', $storage->get('legacy')?->value());

        $storage->clear();
        self::assertSame([], $storage->all());
    }

    public function testSessionStorageCanUseSessionInterfaceNamespaces(): void
    {
        $session = new ArrayBackedSession();
        $storage = new SessionCsrfTokenStorage($session, 'custom_csrf');
        $token = new CsrfToken('profile', 'profile-value', new DateTimeImmutable('2026-01-01 00:00:00'));

        $storage->put($token);

        self::assertTrue($session->has('custom_csrf'));
        self::assertSame($token->toArray(), $session->bag('custom_csrf')->get('profile'));
        self::assertEquals($token, $storage->get('profile'));
    }

    public function testSessionStorageRejectsInvalidNamespacesAndMalformedEntries(): void
    {
        try {
            new SessionCsrfTokenStorage(SessionBag::create(), 'bad namespace');
            self::fail('Expected invalid namespace exception.');
        } catch (InvalidCsrfTokenException $exception) {
            self::assertStringContainsString('Invalid CSRF token id', $exception->getMessage());
        }

        $bag = SessionBag::create();
        $storage = new SessionCsrfTokenStorage($bag);
        $bag->set('broken-object', 123);
        $bag->set('broken-array', ['id' => 'broken-array']);

        foreach (['broken-object', 'broken-array'] as $id) {
            try {
                $storage->get($id);
                self::fail('Expected malformed stored token exception.');
            } catch (InvalidCsrfTokenException $exception) {
                self::assertStringContainsString('contains invalid stored data', $exception->getMessage());
            }
        }
    }
}
