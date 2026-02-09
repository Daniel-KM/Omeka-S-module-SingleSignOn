<?php declare(strict_types=1);

namespace SingleSignOnTest\Mvc\Controller\Plugin;

use CommonTest\AbstractHttpControllerTestCase;
use SingleSignOn\Mvc\Controller\Plugin\IdpMetadata;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Tests for the IdpMetadata controller plugin.
 *
 * The plugin fetches and parses SAML metadata from an IdP URL and extracts:
 * entity_id, entity_name, sso_url, slo_url, sign/crypt certificates, etc.
 */
class IdpMetadataTest extends AbstractHttpControllerTestCase
{
    use SingleSignOnTestTrait;

    /**
     * @var IdpMetadata
     */
    protected $plugin;

    public function setUp(): void
    {
        parent::setUp();
        $this->loginAdmin();
        $this->setupMockHttpClient();
        $this->plugin = $this->createPluginWithController(IdpMetadata::class);
    }

    /**
     * Test that null URL returns null.
     */
    public function testNullUrlReturnsNull(): void
    {
        $result = ($this->plugin)(null, false);
        $this->assertNull($result);
    }

    /**
     * Test that empty URL returns null.
     */
    public function testEmptyUrlReturnsNull(): void
    {
        $result = ($this->plugin)('', false);
        $this->assertNull($result);
    }

    /**
     * Test that an invalid URL returns null.
     */
    public function testInvalidUrlReturnsNull(): void
    {
        $result = ($this->plugin)('not-a-valid-url', false);
        $this->assertNull($result);
    }

    /**
     * Test that a URL returning 404 returns null.
     */
    public function testNotFoundUrlReturnsNull(): void
    {
        $result = ($this->plugin)('https://unknown.example.org/metadata', false);
        $this->assertNull($result);
    }

    /**
     * Test that a URL returning non-XML returns null.
     */
    public function testNonXmlResponseReturnsNull(): void
    {
        $mockClient = $this->getMockHttpClient();
        $mockClient->addResponse('https://bad.example.org/metadata', 'This is not XML', 200);

        $plugin = $this->createPluginWithController(IdpMetadata::class);
        $result = ($plugin)('https://bad.example.org/metadata', false);
        $this->assertNull($result);
    }

    /**
     * Test that valid IdP metadata is correctly parsed.
     */
    public function testValidMetadataReturnsExpectedData(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertNotNull($result);
        $this->assertIsArray($result);
    }

    /**
     * Test that entity ID is correctly extracted.
     */
    public function testEntityIdExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('https://idp.example.org/saml2', $result['entity_id']);
    }

    /**
     * Test that entity name is correctly extracted from UIInfo DisplayName.
     */
    public function testEntityNameExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertNotEmpty($result['entity_name']);
        // First DisplayName should be used (English).
        $this->assertSame('Example Identity Provider', $result['entity_name']);
    }

    /**
     * Test that SSO URL is correctly extracted (HTTP-Redirect binding).
     */
    public function testSsoUrlExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('https://idp.example.org/saml2/sso', $result['sso_url']);
    }

    /**
     * Test that SLO URL is correctly extracted (HTTP-Redirect binding).
     */
    public function testSloUrlExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('https://idp.example.org/saml2/slo', $result['slo_url']);
    }

    /**
     * Test that signing certificates are extracted.
     */
    public function testSigningCertificatesExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertArrayHasKey('sign_x509_certificates', $result);
        $this->assertNotEmpty($result['sign_x509_certificates']);
        $this->assertIsArray($result['sign_x509_certificates']);
    }

    /**
     * Test that encryption certificates are extracted.
     */
    public function testEncryptionCertificatesExtracted(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertArrayHasKey('crypt_x509_certificates', $result);
        $this->assertNotEmpty($result['crypt_x509_certificates']);
        $this->assertIsArray($result['crypt_x509_certificates']);
    }

    /**
     * Test that entity_short_id is derived from entity ID.
     */
    public function testEntityShortIdDerived(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('idp.example.org', $result['entity_short_id']);
    }

    /**
     * Test that host is derived from SSO URL.
     */
    public function testHostDerivedFromSsoUrl(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('idp.example.org', $result['host']);
    }

    /**
     * Test that metadata_url is stored.
     */
    public function testMetadataUrlStored(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertSame('https://idp.example.org/saml2/metadata', $result['metadata_url']);
    }

    /**
     * Test that date is set.
     */
    public function testDateIsSet(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $this->assertArrayHasKey('date', $result);
        $this->assertNotEmpty($result['date']);
    }

    /**
     * Test that all expected keys are present in the result.
     */
    public function testResultHasAllExpectedKeys(): void
    {
        $result = ($this->plugin)('https://idp.example.org/saml2/metadata', false);

        $expectedKeys = [
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

        foreach ($expectedKeys as $key) {
            $this->assertArrayHasKey($key, $result, "Missing key: $key");
        }
    }
}
