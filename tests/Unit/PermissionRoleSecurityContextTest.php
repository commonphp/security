<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\Contracts\SecurityContextInterface;
use CommonPHP\Security\Exceptions\AuthorizationException;
use CommonPHP\Security\Permission;
use CommonPHP\Security\Role;
use CommonPHP\Security\SecurityContext;
use PHPUnit\Framework\TestCase;
use Stringable;

final class PermissionRoleSecurityContextTest extends TestCase
{
    public function testPermissionNormalizesComparesAndStringifies(): void
    {
        $stringable = new class implements Stringable {
            public function __toString(): string
            {
                return ' posts.publish ';
            }
        };

        $permission = new Permission($stringable);

        self::assertSame('posts.publish', $permission->value());
        self::assertSame('posts.publish', $permission->name());
        self::assertSame('posts.publish', (string) $permission);
        self::assertTrue($permission->equals('posts.publish'));
        self::assertFalse($permission->equals('posts.delete'));
        self::assertSame($permission, Permission::from($permission));
        self::assertSame('posts.delete', Permission::from(' posts.delete ')->value());
    }

    public function testPermissionRejectsInvalidNames(): void
    {
        foreach (['   ', 'posts publish', str_repeat('a', Permission::MAX_LENGTH + 1)] as $permission) {
            try {
                new Permission($permission);
                self::fail('Expected invalid permission exception.');
            } catch (AuthorizationException $exception) {
                self::assertStringContainsString('Invalid permission', $exception->getMessage());
            }
        }

        self::assertSame(str_repeat('a', Permission::MAX_LENGTH), (new Permission(str_repeat('a', Permission::MAX_LENGTH)))->value());
    }

    public function testRoleManagesPermissions(): void
    {
        $role = new Role('admin', ['users.read']);

        self::assertSame('admin', $role->name());
        self::assertSame('admin', (string) $role);
        self::assertTrue($role->hasPermission('users.read'));
        self::assertSame($role, $role->grant('users.write', new Permission('users.delete')));
        self::assertSame($role, $role->grant('users.write'));
        self::assertSame(['users.read', 'users.write', 'users.delete'], $role->permissionNames());
        self::assertContainsOnlyInstancesOf(Permission::class, $role->permissions());
        self::assertCount(3, $role);

        $role->revoke('users.write');

        self::assertFalse($role->hasPermission('users.write'));
        self::assertTrue($role->equals('admin'));
        self::assertFalse($role->equals('editor'));
        self::assertSame(['users.read', 'users.delete'], array_keys(iterator_to_array($role)));
        self::assertSame($role, $role->clearPermissions());
        self::assertSame([], $role->permissions());
        self::assertSame($role, Role::from($role));
        self::assertSame('viewer', Role::from(' viewer ')->name());
    }

    public function testRoleRejectsInvalidNames(): void
    {
        foreach (['   ', 'site owner', str_repeat('a', Role::MAX_LENGTH + 1)] as $role) {
            try {
                new Role($role);
                self::fail('Expected invalid role exception.');
            } catch (AuthorizationException $exception) {
                self::assertStringContainsString('Invalid role', $exception->getMessage());
            }
        }

        self::assertSame(str_repeat('a', Role::MAX_LENGTH), (new Role(str_repeat('a', Role::MAX_LENGTH)))->name());
    }

    public function testSecurityContextTracksIdentityRolesPermissionsAndAttributes(): void
    {
        $role = new Role('editor', ['posts.update']);
        $context = SecurityContext::forIdentity(
            ['id' => 10],
            [$role],
            ['posts.create'],
            ['tenant' => 'acme'],
        );

        $role->grant('posts.delete');

        self::assertInstanceOf(SecurityContextInterface::class, $context);
        self::assertTrue($context->isAuthenticated());
        self::assertFalse($context->isGuest());
        self::assertSame(['id' => 10], $context->identity());
        self::assertSame(['id' => 10], $context->user());
        self::assertTrue($context->hasRole('editor'));
        self::assertSame(['editor'], $context->roleNames());
        self::assertTrue($context->hasPermission('posts.create'));
        self::assertTrue($context->hasPermission('posts.update'));
        self::assertFalse($context->hasPermission('posts.delete'));
        self::assertSame(['posts.create'], array_map(
            static fn (Permission $permission): string => $permission->value(),
            $context->directPermissions(),
        ));
        self::assertSame(['posts.create', 'posts.update'], array_map(
            static fn (Permission $permission): string => $permission->value(),
            $context->permissions(),
        ));
        self::assertSame('acme', $context->attribute('tenant'));
        self::assertSame('fallback', $context->attribute('missing', 'fallback'));
        self::assertTrue($context->hasAttribute('tenant'));

        $context->setAttribute('locale', 'en')->removeAttribute('tenant');
        self::assertSame(['locale' => 'en'], $context->attributes());

        $context->removeRole('editor')->revoke('posts.create');
        self::assertFalse($context->hasRole('editor'));
        self::assertFalse($context->hasPermission('posts.create'));
    }

    public function testSecurityContextClonesRoleInputAndOutput(): void
    {
        $role = new Role('publisher', ['posts.publish']);
        $context = new SecurityContext(roles: [$role]);

        $role->grant('posts.delete');
        $returned = $context->roles()[0];
        $returned->grant('posts.archive');

        self::assertTrue($context->hasPermission('posts.publish'));
        self::assertFalse($context->hasPermission('posts.delete'));
        self::assertFalse($context->hasPermission('posts.archive'));
    }

    public function testSecurityContextAuthenticationDefaultsCanBeOverridden(): void
    {
        $guestWithIdentity = new SecurityContext(identity: 'anonymous-user', authenticated: false);
        $authenticatedWithoutIdentity = new SecurityContext(authenticated: true);

        self::assertTrue($guestWithIdentity->isGuest());
        self::assertSame('anonymous-user', $guestWithIdentity->identity());
        self::assertTrue($authenticatedWithoutIdentity->isAuthenticated());
        self::assertNull($authenticatedWithoutIdentity->identity());
        self::assertSame($guestWithIdentity, $guestWithIdentity->removeAttribute('missing'));
    }

    public function testGuestAndLogoutClearAuthenticationState(): void
    {
        $guest = SecurityContext::guest();

        self::assertTrue($guest->isGuest());
        self::assertNull($guest->identity());

        $guest->authenticate('user')->addRole('admin')->grant('admin.access');
        self::assertTrue($guest->isAuthenticated());

        $guest->logout();

        self::assertTrue($guest->isGuest());
        self::assertSame([], $guest->roles());
        self::assertSame([], $guest->permissions());
    }
}
