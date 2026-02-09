<?php declare(strict_types=1);

namespace SingleSignOnTest\Controller;

use CommonTest\AbstractHttpControllerTestCase;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Tests for the SSO controller routes.
 *
 * Note: Full SAML flow tests (login, acs, sls) require a real IdP or mock SAML
 * library, so only route accessibility and basic behavior are tested here.
 */
class SsoControllerTest extends AbstractHttpControllerTestCase
{
    use SingleSignOnTestTrait;

    /**
     * Don't require login for SSO routes (they are public).
     */
    protected bool $requiresLogin = false;

    public function setUp(): void
    {
        parent::setUp();
    }

    /**
     * Test that the SSO default route matches the metadata action.
     */
    public function testDefaultRouteIsMetadata(): void
    {
        $this->dispatch('/sso');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('metadata');
    }

    /**
     * Test that the metadata route matches the correct controller and action.
     */
    public function testMetadataRouteMatchesController(): void
    {
        $this->dispatch('/sso/metadata');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('metadata');
    }

    /**
     * Test that the login route exists and is accessible.
     */
    public function testLoginRouteExists(): void
    {
        // Without IdP, login should redirect back to login page.
        $this->dispatch('/sso/login');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('login');
    }

    /**
     * Test that the login route with an unknown IdP redirects.
     */
    public function testLoginWithUnknownIdpRedirects(): void
    {
        $this->dispatch('/sso/login/nonexistent-idp');
        // Should redirect to login page with error.
        $this->assertResponseStatusCode(302);
    }

    /**
     * Test that the logout route exists and is accessible.
     */
    public function testLogoutRouteExists(): void
    {
        $this->dispatch('/sso/logout');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('logout');
        // Should redirect (no user logged in).
        $this->assertResponseStatusCode(302);
    }

    /**
     * Test that the ACS route exists.
     */
    public function testAcsRouteExists(): void
    {
        $this->dispatch('/sso/acs');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('acs');
    }

    /**
     * Test that the SLS route exists.
     */
    public function testSlsRouteExists(): void
    {
        $this->dispatch('/sso/sls');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('sls');
    }

    /**
     * Test that the IdP constraint allows valid characters.
     */
    public function testIdpRouteAcceptsValidCharacters(): void
    {
        // The idp parameter allows: [a-zA-Z0-9_.:-]+
        $this->dispatch('/sso/login/idp.example.org');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('login');
    }

    /**
     * Test that the metadata action for a specific IdP is dispatched.
     */
    public function testMetadataActionWithIdpParam(): void
    {
        // Configure a test IdP.
        $this->loginAdmin();
        $idpConfig = $this->createTestIdpConfig();
        $this->setSetting('singlesignon_idps', [
            'https://idp.example.org/saml2' => $idpConfig,
        ]);

        $this->setupMockHttpClient();
        $this->dispatch('/sso/metadata/idp.example.org');
        $this->assertControllerName('SingleSignOn\Controller\SsoController');
        $this->assertActionName('metadata');
    }

    /**
     * Test that logged-in user is redirected on login action.
     */
    public function testLoggedInUserRedirectsOnLogin(): void
    {
        $this->requiresLogin = true;
        $this->dispatch('/sso/login');
        $this->assertResponseStatusCode(302);
    }

    /**
     * Test that logged-in user is redirected on ACS action.
     */
    public function testLoggedInUserRedirectsOnAcs(): void
    {
        $this->requiresLogin = true;
        $this->dispatch('/sso/acs');
        $this->assertResponseStatusCode(302);
    }
}
