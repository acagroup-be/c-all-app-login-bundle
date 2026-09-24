<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\Auth;

use DateInterval;
use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Throwable;

use function is_file;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function substr;
use function trim;

/**
 * Parses an id_token issued by the C-all login app and refuses anything that
 * is not RS256-signed with the login app's key, not meant for this client, or
 * outside its validity window.
 */
final class IdTokenVerifier
{
    private const int DEFAULT_LEEWAY_SECONDS = 60;

    private readonly ClockInterface $clock;

    public function __construct(
        private readonly string $publicKey,
        private readonly string $clientId,
        ClockInterface|null $clock = null,
        private readonly int $leewaySeconds = self::DEFAULT_LEEWAY_SECONDS,
    ) {
        $this->clock = $clock ?? new SystemClock(new DateTimeZone('UTC'));
    }

    /**
     * @throws AuthenticationException when the token is malformed, forged, expired or issued for another client
     */
    public function verify(string $jwt): UnencryptedToken
    {
        try {
            $token = (new Parser(new JoseEncoder()))->parse($jwt);
        } catch (Throwable $exception) {
            throw new AuthenticationException('The id_token could not be parsed.', 0, $exception);
        }

        if (! $token instanceof UnencryptedToken) {
            throw new AuthenticationException('The id_token is not a signed JWS.');
        }

        try {
            (new Validator())->assert(
                $token,
                new SignedWith(new Sha256(), $this->loadKey()),
                new PermittedFor($this->clientId),
                new LooseValidAt($this->clock, new DateInterval(sprintf('PT%dS', $this->leewaySeconds))),
            );
        } catch (RequiredConstraintsViolated $exception) {
            throw new AuthenticationException('The id_token was rejected: ' . $exception->getMessage(), 0, $exception);
        }

        return $token;
    }

    /**
     * Accepts the PEM contents, a file path, or a file:// URI.
     */
    private function loadKey(): Key
    {
        $value = trim($this->publicKey);

        if (str_starts_with($value, 'file://')) {
            return InMemory::file(substr($value, 7));
        }

        if (! str_contains($value, '-----BEGIN') && is_file($value)) {
            return InMemory::file($value);
        }

        return InMemory::plainText($value);
    }
}
