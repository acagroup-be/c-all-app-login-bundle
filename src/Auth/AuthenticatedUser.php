<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\Auth;

use Symfony\Component\Security\Core\User\UserInterface;

use function str_starts_with;
use function strtoupper;

final class AuthenticatedUser implements UserInterface
{
    /** @var string[] */
    private array $roles = [];

    /**
     * @param string[] $roles
     */
    public function __construct(
        private readonly string $id,
        private readonly string $companyId,
        private readonly string $name,
        private readonly string $email,
        array $roles,
    ) {
        foreach ($roles as $role) {
            $this->roles[] = strtoupper(str_starts_with($role, 'ROLE_') ? $role : 'ROLE_' . $role);
        }
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getCompanyId(): string
    {
        return $this->companyId;
    }

    public function getUserIdentifier(): string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    #[\Deprecated]
    public function eraseCredentials(): void
    {
    }
}
