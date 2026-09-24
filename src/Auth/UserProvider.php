<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use RuntimeException;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

use function is_string;

/**
 * Users only exist in the login app: this provider re-validates the stored
 * access token on refresh and never loads users by itself.
 *
 * @implements UserProviderInterface<AuthenticatedUser>
 */
final class UserProvider implements UserProviderInterface
{
    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly string $internalLoginUrl,
    ) {
    }

    public function refreshUser(UserInterface $user): AuthenticatedUser
    {
        if (! $user instanceof AuthenticatedUser) {
            throw new UnsupportedUserException();
        }

        $loginToken = $this->requestStack->getSession()->get('login_token');
        if (! is_string($loginToken) || $loginToken === '') {
            throw new UserNotFoundException();
        }

        try {
            (new Client())->get($this->internalLoginUrl . '/api/token/verify', [
                'headers' => ['Authorization' => 'Bearer ' . $loginToken],
            ]);
        } catch (GuzzleException) {
            throw new UserNotFoundException();
        }

        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return $class === AuthenticatedUser::class;
    }

    public function loadUserByIdentifier(string $identifier): AuthenticatedUser
    {
        throw new RuntimeException('The login bundle cannot load users on its own, they come from the id_token.');
    }
}
