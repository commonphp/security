<?php

declare(strict_types=1);

namespace CommonPHP\Security\Tests\Unit;

use CommonPHP\Security\AuthorizationResult;
use CommonPHP\Security\Authorizer;
use CommonPHP\Security\Contracts\AuthorizerInterface;
use CommonPHP\Security\Enums\AccessDecision;
use CommonPHP\Security\Exceptions\AccessDeniedException;
use CommonPHP\Security\Exceptions\AuthorizationException;
use CommonPHP\Security\Exceptions\PolicyNotFoundException;
use CommonPHP\Security\Permission;
use CommonPHP\Security\PolicyRegistry;
use CommonPHP\Security\SecurityContext;
use CommonPHP\Security\Tests\Fixtures\CallbackPolicy;
use PHPUnit\Framework\TestCase;

final class AuthorizationTest extends TestCase
{
    public function testAuthorizationResultWrapsDecisionsAndThrowsForDeniedResults(): void
    {
        $allow = AuthorizationResult::from(true, 'posts.view');
        $deny = AuthorizationResult::deny('Nope.', new Permission('posts.delete'));
        $abstain = AuthorizationResult::abstain('No opinion.', 'posts.review', ['id' => 1], 'review-policy');

        self::assertTrue($allow->isGranted());
        self::assertSame(AccessDecision::Allow, $allow->decision());
        self::assertSame('posts.view', $allow->permission()?->value());
        self::assertTrue($deny->isDenied());
        self::assertSame('Nope.', $deny->reason());
        self::assertTrue($abstain->isAbstain());
        self::assertSame(['id' => 1], $abstain->resource());
        self::assertSame('review-policy', $abstain->policy());

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Nope.');

        $deny->throwIfDenied();
    }

    public function testAuthorizationResultFactoriesAndMetadataHelpers(): void
    {
        $resource = (object) ['id' => 10];
        $explicit = AuthorizationResult::allow('Granted.', 'posts.edit', $resource, 'explicit-policy');
        $filled = AuthorizationResult::from(AuthorizationResult::deny('Denied.'), 'posts.delete', $resource, 'fill-policy');
        $preserved = AuthorizationResult::from($explicit, 'ignored.permission', 'ignored-resource', 'ignored-policy');
        $withPolicy = $filled->withPolicy('override-policy');

        self::assertSame('Granted.', $explicit->reason());
        self::assertSame('posts.edit', $explicit->permission()?->value());
        self::assertSame($resource, $explicit->resource());
        self::assertSame('explicit-policy', $explicit->policy());
        self::assertSame('posts.delete', $filled->permission()?->value());
        self::assertSame($resource, $filled->resource());
        self::assertSame('fill-policy', $filled->policy());
        self::assertSame('explicit-policy', $preserved->policy());
        self::assertSame('override-policy', $withPolicy->policy());
        self::assertSame('fill-policy', $filled->policy());

        $explicit->throwIfDenied();

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Custom denial.');

        $filled->throwIfDenied('Custom denial.');
    }

    public function testAuthorizerAllowsContextPermissionsAndDeniesMissingPermissions(): void
    {
        $authorizer = new Authorizer();
        $context = new SecurityContext(permissions: ['posts.view']);

        self::assertInstanceOf(AuthorizerInterface::class, $authorizer);
        self::assertTrue($authorizer->can($context, 'posts.view'));
        self::assertFalse($authorizer->cannot($context, 'posts.view'));
        self::assertFalse($authorizer->can($context, 'posts.delete'));

        $this->expectException(AccessDeniedException::class);

        $authorizer->authorize($context, 'posts.delete');
    }

    public function testPoliciesCanGrantDenyAndAbstain(): void
    {
        $context = new SecurityContext(permissions: ['posts.update']);
        $resource = ['owner' => 1];
        $allowPolicy = new CallbackPolicy(
            'post-owner',
            'posts.delete',
            static fn (): AuthorizationResult => AuthorizationResult::allow('Owner can delete.'),
        );
        $denyPolicy = new CallbackPolicy(
            'post-lock',
            'posts.update',
            static fn (): AuthorizationResult => AuthorizationResult::deny('Post is locked.'),
        );
        $abstainPolicy = new CallbackPolicy(
            'post-review',
            'posts.review',
            static fn (): AccessDecision => AccessDecision::Abstain,
        );
        $authorizer = Authorizer::withPolicies([$allowPolicy, $denyPolicy, $abstainPolicy]);

        $allowed = $authorizer->decide($context, 'posts.delete', $resource);
        $denied = $authorizer->decide($context, 'posts.update', $resource);
        $abstained = $authorizer->decide($context, 'posts.review', $resource);

        self::assertTrue($allowed->isGranted());
        self::assertSame('post-owner', $allowed->policy());
        self::assertSame('posts.delete', $allowed->permission()?->value());
        self::assertSame($resource, $allowed->resource());
        self::assertTrue($denied->isDenied());
        self::assertSame('Post is locked.', $denied->reason());
        self::assertTrue($abstained->isDenied());
        self::assertStringContainsString('No security policy granted', (string) $abstained->reason());
    }

    public function testDenyPoliciesWinOverEarlierAllowPolicies(): void
    {
        $authorizer = Authorizer::withPolicies([
            new CallbackPolicy(
                'allowing-policy',
                'posts.publish',
                static fn (): bool => true,
            ),
            new CallbackPolicy(
                'denying-policy',
                'posts.publish',
                static fn (): AuthorizationResult => AuthorizationResult::deny('Publication is locked.'),
            ),
        ]);

        $result = $authorizer->decide(new SecurityContext(), 'posts.publish');

        self::assertTrue($result->isDenied());
        self::assertSame('denying-policy', $result->policy());
        self::assertSame('Publication is locked.', $result->reason());
    }

    public function testContextPermissionIsFallbackWhenPoliciesAbstain(): void
    {
        $policy = new CallbackPolicy(
            'review-policy',
            'posts.review',
            static fn (): AccessDecision => AccessDecision::Abstain,
        );
        $authorizer = Authorizer::withPolicies([$policy]);
        $context = new SecurityContext(permissions: ['posts.review']);

        self::assertTrue($authorizer->can($context, 'posts.review'));
    }

    public function testPolicyRegistryRegistersFindsMatchesAndRemovesPolicies(): void
    {
        $policy = new CallbackPolicy(
            'post-view',
            'posts.view',
            static fn (): bool => true,
        );
        $registry = new PolicyRegistry();

        self::assertSame($registry, $registry->add($policy));
        self::assertTrue($registry->has('post-view'));
        self::assertSame($policy, $registry->get('post-view'));
        self::assertSame(['post-view'], $registry->names());
        self::assertSame([$policy], $registry->matching('posts.view'));
        self::assertCount(1, $registry);
        self::assertSame(['post-view' => $policy], iterator_to_array($registry));

        $registry->remove('post-view');

        self::assertFalse($registry->has('post-view'));

        $this->expectException(PolicyNotFoundException::class);

        $registry->get('post-view');
    }

    public function testPolicyRegistryConstructsOverridesClearsAndMatchesResources(): void
    {
        $viewPolicy = new CallbackPolicy('view', 'posts.view', static fn (): bool => true);
        $firstUpdatePolicy = new CallbackPolicy('update', 'posts.update', static fn (): bool => false);
        $secondUpdatePolicy = new CallbackPolicy('update-replacement', 'posts.update', static fn (): bool => true);
        $resourcePolicy = new CallbackPolicy(
            'resource-policy',
            'ignored',
            static fn (): bool => true,
            static fn (Permission $permission, mixed $resource): bool => $permission->equals('posts.archive')
                && is_array($resource)
                && ($resource['locked'] ?? false) === true,
        );

        $registry = new PolicyRegistry([
            'read-posts' => $viewPolicy,
            $firstUpdatePolicy,
            $resourcePolicy,
        ]);

        self::assertSame(['read-posts', 'update', 'resource-policy'], $registry->names());
        self::assertSame($registry, $registry->add($secondUpdatePolicy, 'update'));
        self::assertSame($secondUpdatePolicy, $registry->get('update'));
        self::assertSame([$resourcePolicy], $registry->matching('posts.archive', ['locked' => true]));
        self::assertSame([], $registry->matching('posts.archive', ['locked' => false]));
        self::assertSame($registry, $registry->remove('missing-policy'));
        self::assertSame($registry, $registry->clear());
        self::assertSame([], $registry->all());
        self::assertCount(0, $registry);
    }

    public function testPolicyRegistryRejectsBlankNames(): void
    {
        $registry = new PolicyRegistry();

        $this->expectException(AuthorizationException::class);

        $registry->add(new CallbackPolicy('policy', 'posts.view', static fn (): bool => true), '   ');
    }
}
