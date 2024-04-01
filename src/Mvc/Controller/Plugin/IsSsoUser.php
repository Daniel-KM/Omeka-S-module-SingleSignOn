<?php declare(strict_types=1);

namespace SingleSignOn\Mvc\Controller\Plugin;

use Doctrine\ORM\EntityManager;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use Omeka\Entity\User;

class IsSsoUser extends AbstractPlugin
{
    /**
     * @var \Doctrine\ORM\EntityManager
     */
    protected $entityManager;

    public function __construct(EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Check if a user is authenticated via module Single Sign-On.
     */
    public function __invoke(?User $user): bool
    {
        if ($user === null) {
            return false;
        }

        // Use the connection to avoid issues with setTargetId() and multiple
        // user ids (it is not possible to reset it to previous target id).

        /** @var \Omeka\Entity\UserSetting $userSetting */
        $userSetting = $this->entityManager->find(\Omeka\Entity\UserSetting::class, [
            'id' => 'connection_authenticator',
            'user' => $user,
        ]);
        return $userSetting
            && $userSetting->getValue() === 'SingleSignOn';
    }
}
