<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\Tests\Auth;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use vBridgeCloud\CallLoginBundle\Auth\IdTokenVerifier;

use function base64_encode;
use function json_encode;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function rtrim;
use function strtr;

use const OPENSSL_KEYTYPE_RSA;

final class IdTokenVerifierTest extends TestCase
{
    private const string CLIENT_ID = 'reporting';

    private string $privateKey;

    private string $publicKey;

    private FrozenClock $clock;

    protected function setUp(): void
    {
        [$this->privateKey, $this->publicKey] = self::generateKeyPair();

        $this->clock = new FrozenClock(new DateTimeImmutable('2026-08-27 12:00:00 UTC'));
    }

    public function testItAcceptsATokenSignedByTheLoginAppForThisClient(): void
    {
        $token = $this->verifier()->verify($this->issue($this->privateKey));

        self::assertSame('jane@example.test', $token->claims()->get('sub'));
        self::assertSame(['appuser'], $token->claims()->get('roles'));
    }

    public function testItAcceptsAPublicKeyGivenAsAFile(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'pub');
        file_put_contents($path, $this->publicKey);

        try {
            $verifier = new IdTokenVerifier($path, self::CLIENT_ID, $this->clock);
            self::assertSame('jane@example.test', $verifier->verify($this->issue($this->privateKey))->claims()->get('sub'));

            $verifier = new IdTokenVerifier('file://' . $path, self::CLIENT_ID, $this->clock);
            self::assertSame('jane@example.test', $verifier->verify($this->issue($this->privateKey))->claims()->get('sub'));
        } finally {
            unlink($path);
        }
    }

    public function testItRejectsATokenSignedWithAnotherKey(): void
    {
        [$otherPrivateKey] = self::generateKeyPair();

        $this->expectException(AuthenticationException::class);
        $this->verifier()->verify($this->issue($otherPrivateKey));
    }

    public function testItRejectsAnUnsignedToken(): void
    {
        // An unsigned token (alg "none") with arbitrary claims must be rejected.
        $header  = self::base64Url(json_encode(['typ' => 'JWT', 'alg' => 'none']));
        $payload = self::base64Url(json_encode([
            'aud' => self::CLIENT_ID,
            'sub' => 'admin@example.test',
            'iat' => 1787832000,
            'exp' => 1787853600,
            'roles' => ['admin'],
        ]));

        $this->expectException(AuthenticationException::class);
        $this->verifier()->verify($header . '.' . $payload . '.');
    }

    public function testItRejectsATokenMeantForAnotherClient(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->verifier()->verify($this->issue($this->privateKey, audience: 'translations'));
    }

    public function testItRejectsAnExpiredToken(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->verifier()->verify($this->issue($this->privateKey, expiresAt: new DateTimeImmutable('2026-08-27 11:00:00 UTC')));
    }

    public function testItToleratesClockSkewWithinTheLeeway(): void
    {
        $token = $this->verifier()->verify(
            $this->issue($this->privateKey, expiresAt: new DateTimeImmutable('2026-08-27 11:59:30 UTC')),
        );

        self::assertSame('jane@example.test', $token->claims()->get('sub'));
    }

    public function testItRejectsGarbage(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->verifier()->verify('not-a-jwt');
    }

    private function verifier(): IdTokenVerifier
    {
        return new IdTokenVerifier($this->publicKey, self::CLIENT_ID, $this->clock);
    }

    private function issue(
        string $privateKey,
        string $audience = self::CLIENT_ID,
        DateTimeImmutable|null $expiresAt = null,
    ): string {
        $now = $this->clock->now();

        return (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
            ->permittedFor($audience)
            ->issuedBy('https://login.c-all.test')
            ->issuedAt($now)
            ->expiresAt($expiresAt ?? $now->modify('+6 hours'))
            ->relatedTo('jane@example.test')
            ->withClaim('id', 'ed7002f0-e649-4a8f-a139-7663869c6e82')
            ->withClaim('roles', ['appuser'])
            ->getToken(new Sha256(), InMemory::plainText($privateKey))
            ->toString();
    }

    /**
     * @return array{string, string} private and public key, PEM
     */
    private static function generateKeyPair(): array
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);

        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        return [$privateKey, $details['key']];
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
