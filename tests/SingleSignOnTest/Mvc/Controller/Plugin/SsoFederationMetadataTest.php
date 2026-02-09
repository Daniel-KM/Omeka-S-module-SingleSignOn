<?php declare(strict_types=1);

namespace SingleSignOnTest\Mvc\Controller\Plugin;

use CommonTest\AbstractHttpControllerTestCase;
use SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Tests for the SsoFederationMetadata controller plugin.
 *
 * The plugin fetches and parses SAML federation metadata (EntitiesDescriptor)
 * and extracts individual IdP data from it.
 */
class SsoFederationMetadataTest extends AbstractHttpControllerTestCase
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

    /**
     * Test that null URL returns null.
     */
    public function testNullUrlReturnsNull(): void
    {
        $result = ($this->plugin)(null, null, false);
        $this->assertNull($result);
    }

    /**
     * Test that empty URL returns null.
     */
    public function testEmptyUrlReturnsNull(): void
    {
        $result = ($this->plugin)('', null, false);
        $this->assertNull($result);
    }

    /**
     * Test that an invalid URL returns null.
     */
    public function testInvalidUrlReturnsNull(): void
    {
        $result = ($this->plugin)('https://not a valid url', null, false);
        $this->assertNull($result);
    }

    /**
     * Test that a URL returning 404 returns null.
     */
    public function testNotFoundUrlReturnsNull(): void
    {
        $result = ($this->plugin)('https://unknown.example.org/metadata', null, false);
        $this->assertNull($result);
    }

    /**
     * Test that non-XML response returns null.
     */
    public function testNonXmlResponseReturnsNull(): void
    {
        $mockClient = $this->getMockHttpClient();
        $mockClient->addResponse('https://bad.example.org/federation', 'Not XML content', 200);

        $plugin = $this->createPluginWithController(SsoFederationMetadata::class);
        $result = ($plugin)('https://bad.example.org/federation', null, false);
        $this->assertNull($result);
    }

    /**
     * Test that valid federation metadata returns all IdPs.
     */
    public function testValidFederationReturnsAllIdps(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $this->assertNotNull($result);
        $this->assertIsArray($result);
        // Federation fixture has 2 IdPs + 1 SP. The plugin returns all
        // EntityDescriptors (including SP ones that have no SSO URLs).
        $this->assertGreaterThanOrEqual(2, count($result));
    }

    /**
     * Test that each IdP in the federation has expected keys.
     */
    public function testFederationIdpsHaveExpectedKeys(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $expectedKeys = [
            'federation_url',
            'metadata_url',
            'entity_id',
            'entity_name',
            'entity_short_id',
            'host',
            'sso_url',
            'slo_url',
            'sign_x509_certificates',
            'crypt_x509_certificates',
            'date',
        ];

        foreach ($result as $entityId => $idp) {
            foreach ($expectedKeys as $key) {
                $this->assertArrayHasKey($key, $idp, "IdP $entityId missing key: $key");
            }
        }
    }

    /**
     * Test that first IdP data is correctly extracted.
     */
    public function testFirstIdpDataIsCorrect(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $this->assertArrayHasKey('https://idp1.example.org/saml2', $result);

        $idp1 = $result['https://idp1.example.org/saml2'];
        $this->assertSame('https://idp1.example.org/saml2', $idp1['entity_id']);
        $this->assertSame('University Alpha', $idp1['entity_name']);
        $this->assertSame('https://idp1.example.org/saml2/sso', $idp1['sso_url']);
        $this->assertSame('https://idp1.example.org/saml2/slo', $idp1['slo_url']);
        $this->assertNotEmpty($idp1['sign_x509_certificates']);
    }

    /**
     * Test that second IdP data is correctly extracted.
     */
    public function testSecondIdpDataIsCorrect(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $this->assertArrayHasKey('https://idp2.example.org/adfs/services/trust', $result);

        $idp2 = $result['https://idp2.example.org/adfs/services/trust'];
        $this->assertSame('https://idp2.example.org/adfs/services/trust', $idp2['entity_id']);
        $this->assertSame('University Beta', $idp2['entity_name']);
        $this->assertSame('https://idp2.example.org/adfs/ls/', $idp2['sso_url']);
        $this->assertSame('https://idp2.example.org/adfs/ls/', $idp2['slo_url']);
    }

    /**
     * Test that second IdP has encryption certificates.
     */
    public function testSecondIdpHasEncryptionCertificates(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $idp2 = $result['https://idp2.example.org/adfs/services/trust'];
        $this->assertNotEmpty($idp2['crypt_x509_certificates']);
    }

    /**
     * Test that filtering by entity ID returns only that IdP.
     */
    public function testFilterByEntityIdReturnsSingleIdp(): void
    {
        $result = ($this->plugin)(
            'https://federation.example.org/metadata/idps.xml',
            'https://idp1.example.org/saml2',
            false
        );

        $this->assertNotNull($result);
        $this->assertIsArray($result);
        // When filtering by entity ID, the plugin returns the single IdP
        // data (not wrapped in entity_id key).
        $this->assertArrayHasKey('entity_id', $result);
        $this->assertSame('https://idp1.example.org/saml2', $result['entity_id']);
    }

    /**
     * Test that federation_url is stored in each IdP config.
     */
    public function testFederationUrlStoredInIdps(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        foreach ($result as $entityId => $idp) {
            $this->assertSame(
                'https://federation.example.org/metadata/idps.xml',
                $idp['federation_url'],
                "Federation URL not set for $entityId"
            );
        }
    }

    /**
     * Test that metadata_url is null for federated IdPs.
     */
    public function testMetadataUrlIsNullForFederatedIdps(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        foreach ($result as $entityId => $idp) {
            $this->assertNull($idp['metadata_url'], "metadata_url should be null for $entityId");
        }
    }

    /**
     * Test that entity_short_id is correctly derived for each IdP.
     */
    public function testEntityShortIdDerived(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $idp1 = $result['https://idp1.example.org/saml2'] ?? null;
        $this->assertNotNull($idp1);
        $this->assertSame('idp1.example.org', $idp1['entity_short_id']);

        $idp2 = $result['https://idp2.example.org/adfs/services/trust'] ?? null;
        $this->assertNotNull($idp2);
        $this->assertSame('idp2.example.org', $idp2['entity_short_id']);
    }

    /**
     * Test that host is derived from SSO URL.
     */
    public function testHostDerivedFromSsoUrl(): void
    {
        $result = ($this->plugin)('https://federation.example.org/metadata/idps.xml', null, false);

        $idp1 = $result['https://idp1.example.org/saml2'];
        $this->assertSame('idp1.example.org', $idp1['host']);

        $idp2 = $result['https://idp2.example.org/adfs/services/trust'];
        $this->assertSame('idp2.example.org', $idp2['host']);
    }

    /**
     * Test that filtering by non-existent entity ID returns data with empty SSO URL.
     *
     * The plugin still creates an entry for the requested entity ID but
     * extracts no SSO/SLO URLs since the EntityDescriptor doesn't exist.
     */
    public function testFilterByNonExistentEntityIdHasNoSsoUrl(): void
    {
        $result = ($this->plugin)(
            'https://federation.example.org/metadata/idps.xml',
            'https://nonexistent.example.org/saml2',
            false
        );

        $this->assertIsArray($result);
        // The entry exists but with empty SSO data.
        $this->assertEmpty($result['sso_url']);
    }
}
