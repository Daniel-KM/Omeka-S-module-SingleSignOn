<?php declare(strict_types=1);

namespace SingleSignOnTest\Mvc\Controller\Plugin;

use CommonTest\AbstractHttpControllerTestCase;
use SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Edge case tests for SsoFederationMetadata plugin.
 *
 * Tests the non-namespaced XML path and other edge cases in federation
 * metadata parsing.
 */
class SsoFederationMetadataEdgeCasesTest extends AbstractHttpControllerTestCase
{
    use SingleSignOnTestTrait;

    /**
     * @var SsoFederationMetadata
     */
    protected $plugin;

    public function setUp(): void
    {
        parent::setUp();
        $this->loginAdmin();
        $this->setupMockHttpClient();
        $this->plugin = $this->createPluginWithController(SsoFederationMetadata::class);
    }

    // =========================================================================
    // No-namespace federation metadata (else branch)
    // =========================================================================

    /**
     * Test that federation metadata without namespaces is parsed correctly.
     */
    public function testNoNamespaceFederationIsParsed(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $this->assertNotNull($result, 'No-namespace federation metadata should be parsed');
        $this->assertIsArray($result);
        $this->assertGreaterThanOrEqual(2, count($result));
    }

    /**
     * Test entity IDs are extracted from no-namespace federation.
     */
    public function testNoNamespaceFederationEntityIds(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $this->assertArrayHasKey('https://idp-nons1.example.org/saml2', $result);
        $this->assertArrayHasKey('https://idp-nons2.example.org/saml2', $result);
    }

    /**
     * Test SSO URLs from no-namespace federation.
     */
    public function testNoNamespaceFederationSsoUrls(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $idp1 = $result['https://idp-nons1.example.org/saml2'];
        $this->assertSame('https://idp-nons1.example.org/saml2/sso', $idp1['sso_url']);

        $idp2 = $result['https://idp-nons2.example.org/saml2'];
        $this->assertSame('https://idp-nons2.example.org/saml2/sso', $idp2['sso_url']);
    }

    /**
     * Test entity name fallback to OrganizationName in no-namespace federation.
     *
     * In no-namespace XML, the UIInfo DisplayName xpath may not work because
     * the code uses "mdui:DisplayName" prefix even without namespace registration.
     */
    public function testNoNamespaceFederationEntityNames(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $idp1 = $result['https://idp-nons1.example.org/saml2'];
        // OrganizationName should be used as fallback.
        $this->assertSame('No-NS University One', $idp1['entity_name']);
    }

    /**
     * Test that filtering by entity ID works in no-namespace federation.
     */
    public function testNoNamespaceFederationFilterByEntityId(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            'https://idp-nons2.example.org/saml2',
            false
        );

        $this->assertNotNull($result);
        $this->assertSame('https://idp-nons2.example.org/saml2', $result['entity_id']);
        $this->assertSame('https://idp-nons2.example.org/saml2/sso', $result['sso_url']);
    }

    /**
     * Test signing certificates in no-namespace federation.
     */
    public function testNoNamespaceFederationSigningCertificates(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        foreach ($result as $entityId => $idp) {
            $this->assertNotEmpty(
                $idp['sign_x509_certificates'],
                "IdP $entityId should have signing certificates"
            );
        }
    }

    /**
     * Test SLO URL for IdP without SingleLogoutService in no-namespace federation.
     */
    public function testNoNamespaceFederationIdpWithoutSlo(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $idp1 = $result['https://idp-nons1.example.org/saml2'];
        $this->assertEmpty($idp1['slo_url'], 'IdP without SLO should have empty slo_url');

        $idp2 = $result['https://idp-nons2.example.org/saml2'];
        $this->assertNotEmpty($idp2['slo_url'], 'IdP with SLO should have slo_url');
    }

    /**
     * Test that second IdP in no-namespace federation has no entity_name.
     *
     * The second IdP has no Organization element — entity_name should be empty.
     */
    public function testNoNamespaceFederationIdpWithoutOrganization(): void
    {
        $result = ($this->plugin)(
            'https://federation-nons.example.org/metadata/idps.xml',
            null,
            false
        );

        $idp2 = $result['https://idp-nons2.example.org/saml2'];
        // No DisplayName, no OrganizationName — entity_name should be empty.
        $this->assertEmpty($idp2['entity_name']);
    }

    // =========================================================================
    // Local file path (not URL)
    // =========================================================================

    /**
     * Test that a local file path to a non-existent file returns null.
     */
    public function testLocalFileNonExistentReturnsNull(): void
    {
        $result = ($this->plugin)('/tmp/nonexistent-federation.xml', null, false);

        $this->assertNull($result);
    }
}
