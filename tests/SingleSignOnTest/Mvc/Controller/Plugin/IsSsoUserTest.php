<?php declare(strict_types=1);

namespace SingleSignOnTest\Mvc\Controller\Plugin;

use CommonTest\AbstractHttpControllerTestCase;
use Omeka\Entity\User;
use Omeka\Entity\UserSetting;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Tests for the IsSsoUser controller plugin.
 *
 * The plugin checks if a user was authenticated via SingleSignOn by looking
 * at the 'connection_authenticator' user setting.
 */
class IsSsoUserTest extends AbstractHttpControllerTestCase
{
    use SingleSignOnTestTrait;

    public function setUp(): void
    {
        parent::setUp();
        $this->loginAdmin();
    }

    /**
     * Get the IsSsoUser plugin from the controller plugin manager.
     */
    protected function getIsSsoUserPlugin(): \SingleSignOn\Mvc\Controller\Plugin\IsSsoUser
    {
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        return $plugins->get('isSsoUser');
    }

    /**
     * Test that null user returns false.
     */
    public function testNullUserReturnsFalse(): void
    {
        $plugin = $this->getIsSsoUserPlugin();
        $this->assertFalse($plugin(null));
    }

    /**
     * Test that admin user (local auth) returns false.
     */
    public function testLocalUserReturnsFalse(): void
    {
        $plugin = $this->getIsSsoUserPlugin();
        $em = $this->getEntityManager();
        $admin = $em->getRepository(User::class)->findOneBy(['email' => 'admin@example.com']);
        $this->assertFalse($plugin($admin));
    }

    /**
     * Test that a user with SSO connection_authenticator returns true.
     */
    public function testSsoUserReturnsTrue(): void
    {
        $em = $this->getEntityManager();

        // Create a test user.
        $user = new User();
        $user->setEmail('sso-test-user@example.org');
        $user->setName('SSO Test User');
        $user->setRole('researcher');
        $user->setIsActive(true);
        $em->persist($user);
        $em->flush();

        // Set the connection_authenticator user setting.
        $userSetting = new UserSetting();
        $userSetting->setId('connection_authenticator');
        $userSetting->setUser($user);
        $userSetting->setValue('SingleSignOn');
        $em->persist($userSetting);
        $em->flush();

        $plugin = $this->getIsSsoUserPlugin();
        $this->assertTrue($plugin($user));

        // Cleanup.
        $em->remove($userSetting);
        $em->remove($user);
        $em->flush();
    }

    /**
     * Test that a user with different authenticator returns false.
     */
    public function testNonSsoAuthenticatorReturnsFalse(): void
    {
        $em = $this->getEntityManager();

        // Create a test user.
        $user = new User();
        $user->setEmail('other-auth-user@example.org');
        $user->setName('Other Auth User');
        $user->setRole('researcher');
        $user->setIsActive(true);
        $em->persist($user);
        $em->flush();

        // Set a different authenticator.
        $userSetting = new UserSetting();
        $userSetting->setId('connection_authenticator');
        $userSetting->setUser($user);
        $userSetting->setValue('SomeOtherModule');
        $em->persist($userSetting);
        $em->flush();

        $plugin = $this->getIsSsoUserPlugin();
        $this->assertFalse($plugin($user));

        // Cleanup.
        $em->remove($userSetting);
        $em->remove($user);
        $em->flush();
    }
}
