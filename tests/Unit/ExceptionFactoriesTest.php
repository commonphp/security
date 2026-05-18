<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Exceptions\AccessDeniedException;
use CommonPHP\Security\Exceptions\AuthorizationException;
use CommonPHP\Security\Exceptions\InvalidCsrfTokenException;
use CommonPHP\Security\Exceptions\PasswordHashException;
use CommonPHP\Security\Exceptions\PolicyNotFoundException;
use CommonPHP\Security\Exceptions\SecurityException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;

final class ExceptionFactoriesTest extends TestCase
{
    public function testSecurityExceptionFactory(): void
    {
        $exception = SecurityException::because('Something failed.');

        self::assertSame('Something failed.', $exception->getMessage());
    }

    public function testAccessDeniedFactories(): void
    {
        self::assertSame(
            'Access denied for permission "posts.delete".',
            AccessDeniedException::forPermission('posts.delete')->getMessage(),
        );
        self::assertSame(
            'Custom denial.',
            AccessDeniedException::forPermission('posts.delete', 'Custom denial.')->getMessage(),
        );
        self::assertSame(
            'No policy allowed this.',
            AccessDeniedException::forResult(AuthorizationResult::deny('No policy allowed this.'))->getMessage(),
        );
        self::assertSame(
            'Access denied for permission "posts.archive".',
            AccessDeniedException::forResult(AuthorizationResult::deny(permission: 'posts.archive'))->getMessage(),
        );
        self::assertSame(
            'Access denied.',
            AccessDeniedException::forResult(AuthorizationResult::deny())->getMessage(),
        );
    }

    public function testAuthorizationExceptionFactories(): void
    {
        self::assertStringContainsString('<empty>', AuthorizationException::invalidPermission('')->getMessage());
        self::assertStringContainsString('because', AuthorizationException::invalidPermission('bad', 'because')->getMessage());
        self::assertStringContainsString('<empty>', AuthorizationException::invalidRole('')->getMessage());
        self::assertStringContainsString('because', AuthorizationException::invalidRole('bad', 'because')->getMessage());
        self::assertStringContainsString('<empty>', AuthorizationException::invalidPolicyName('')->getMessage());
        self::assertStringContainsString('maybe', AuthorizationException::invalidDecision('maybe')->getMessage());
        self::assertStringContainsString(
            stdClass::class,
            AuthorizationException::invalidPolicyResult('policy', new stdClass())->getMessage(),
        );
    }

    public function testCsrfExceptionFactories(): void
    {
        self::assertStringContainsString('<empty>', InvalidCsrfTokenException::invalidId('')->getMessage());
        self::assertSame('Invalid CSRF token value.', InvalidCsrfTokenException::invalidValue()->getMessage());
        self::assertStringContainsString('was not found', InvalidCsrfTokenException::missing('token')->getMessage());
        self::assertStringContainsString('does not match', InvalidCsrfTokenException::mismatch('token')->getMessage());
        self::assertStringContainsString('has expired', InvalidCsrfTokenException::expired('token')->getMessage());
        self::assertStringContainsString('invalid stored data', InvalidCsrfTokenException::malformed('token')->getMessage());
        self::assertStringContainsString(
            'entropy',
            InvalidCsrfTokenException::invalidGeneratorConfig('entropy too low')->getMessage(),
        );

        $previous = new RuntimeException('random failed');
        $exception = InvalidCsrfTokenException::generationFailed($previous);

        self::assertSame('Unable to generate a CSRF token.', $exception->getMessage());
        self::assertSame($previous, $exception->getPrevious());
    }

    public function testPasswordHashAndPolicyExceptionFactories(): void
    {
        $previous = new RuntimeException('bad algorithm');

        self::assertSame('Password could not be hashed.', PasswordHashException::forHashing($previous)->getMessage());
        self::assertSame($previous, PasswordHashException::forHashing($previous)->getPrevious());
        self::assertSame(
            'Password hash rehash requirements could not be checked.',
            PasswordHashException::forRehashCheck($previous)->getMessage(),
        );
        self::assertSame($previous, PasswordHashException::forRehashCheck($previous)->getPrevious());
        self::assertSame(
            'No security policy is registered with name "missing".',
            PolicyNotFoundException::forName('missing')->getMessage(),
        );
    }
}
