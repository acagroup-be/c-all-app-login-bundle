<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Throwable;

use function is_array;
use function is_string;
use function json_decode;

final class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly string $internalLoginUrl,
        private readonly string $publicLoginUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $oauthRedirectPath,
        private readonly string $loginRedirectPath,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly IdTokenVerifier $idTokenVerifier,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->attributes->get('_route') === $this->oauthRedirectPath;
    }

    public function authenticate(Request $request): Passport
    {
        if ($request->query->has('code')) {
            [$idToken, $accessToken] = $this->exchangeCode((string) $request->query->get('code'));
        } elseif ($request->query->has('access_token') && $request->query->has('id_token')) {
            // The login app short-circuits the code exchange when it still holds a valid
            // token for this client. The id_token signature check below is what makes
            // trusting these query parameters acceptable.
            $idToken     = (string) $request->query->get('id_token');
            $accessToken = (string) $request->query->get('access_token');
        } else {
            throw new BadCredentialsException();
        }

        $token  = $this->idTokenVerifier->verify($idToken);
        $claims = $token->claims();

        $userIdentifier = $claims->get('sub');
        if (! is_string($userIdentifier) || $userIdentifier === '') {
            throw new AuthenticationException('The id_token carries no subject.');
        }

        $request->getSession()->set('login_token', $accessToken);

        return new SelfValidatingPassport(new UserBadge(
            $userIdentifier,
            static function () use ($claims): UserInterface {
                return new AuthenticatedUser(
                    (string) $claims->get('id'),
                    (string) $claims->get('company_id'),
                    (string) $claims->get('name'),
                    (string) $claims->get('email'),
                    is_array($claims->get('roles')) ? $claims->get('roles') : [],
                );
            },
        ));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        try {
            $url = $this->urlGenerator->generate((string) $request->query->get('state'));
        } catch (Throwable) {
            $url = $this->urlGenerator->generate($this->loginRedirectPath);
        }

        return new RedirectResponse($url);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new RedirectResponse($this->publicLoginUrl . '/login');
    }

    /**
     * @return array{string, string} id_token and access_token
     */
    private function exchangeCode(string $code): array
    {
        try {
            $response = (new Client())->request(
                'POST',
                $this->internalLoginUrl . '/access_token',
                [
                    'form_params' => [
                        'grant_type' => 'authorization_code',
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                        'redirect_uri' => $this->urlGenerator->generate(
                            $this->oauthRedirectPath,
                            [],
                            UrlGeneratorInterface::ABSOLUTE_URL,
                        ),
                        'code' => $code,
                    ],
                ],
            );
        } catch (GuzzleException $exception) {
            throw new AuthenticationException('The authorization code could not be exchanged.', 0, $exception);
        }

        $payload = json_decode((string) $response->getBody(), true);
        if (! is_array($payload) || ! is_string($payload['id_token'] ?? null) || ! is_string($payload['access_token'] ?? null)) {
            throw new AuthenticationException('The login app returned no usable token.');
        }

        return [$payload['id_token'], $payload['access_token']];
    }
}
