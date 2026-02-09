<?php declare(strict_types=1);

namespace SingleSignOnTest\Mvc\Controller\Plugin;

use CommonTest\AbstractHttpControllerTestCase;
use SingleSignOn\Mvc\Controller\Plugin\IdpMetadata;
use SingleSignOnTest\SingleSignOnTestTrait;

/**
 * Edge case tests for IdpMetadata plugin.
 *
 * These tests probe less common SAML metadata formats to find potential bugs
 * in the XML parsing logic.
 */
class IdpMetadataEdgeCasesTest extends AbstractHttpControllerTestCase
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

    // =========================================================================
    // No-namespace metadata (else branch in parsing)
    // =========================================================================

    /**
     * Test that metadata without XML namespaces is parsed correctly.
     *
     * The IdpMetadata plugin has two code paths: one for namespaced XML
     * and one for XML without namespaces. This tests the latter.
     */
    public function testNoNamespaceMetadataIsParsed(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertNotNull($result, 'No-namespace metadata should be parsed');
        $this->assertIsArray($result);
    }

    /**
     * Test entity ID extraction from no-namespace metadata.
     */
    public function testNoNamespaceEntityId(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertSame('https://idp-nons.example.org/saml2', $result['entity_id']);
    }

    /**
     * Test SSO URL extraction from no-namespace metadata.
     */
    public function testNoNamespaceSsoUrl(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertSame('https://idp-nons.example.org/saml2/sso', $result['sso_url']);
    }

    /**
     * Test entity name fallback to OrganizationName (no DisplayName in no-namespace).
     */
    public function testNoNamespaceEntityNameFromOrganization(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertSame('No-Namespace University', $result['entity_name']);
    }

    /**
     * Test signing certificates extraction from no-namespace metadata.
     */
    public function testNoNamespaceSigningCertificates(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertNotEmpty($result['sign_x509_certificates']);
    }

    /**
     * Test SLO URL is empty when not present in no-namespace metadata.
     */
    public function testNoNamespaceNoSloUrl(): void
    {
        $result = ($this->plugin)('https://idp-nons.example.org/saml2/metadata', false);

        $this->assertEmpty($result['slo_url']);
    }

    // =========================================================================
    // Minimal metadata (fallbacks)
    // =========================================================================

    /**
     * Test metadata without DisplayName falls back to OrganizationName.
     */
    public function testMinimalMetadataFallsBackToOrganizationName(): void
    {
        $result = ($this->plugin)('https://idp-minimal.example.org/saml2/metadata', false);

        $this->assertNotNull($result);
        // No UIInfo/DisplayName; should use OrganizationName.
        $this->assertSame('Minimal University', $result['entity_name']);
    }

    /**
     * Test metadata with no SLO URL returns empty string.
     */
    public function testMinimalMetadataNoSloUrl(): void
    {
        $result = ($this->plugin)('https://idp-minimal.example.org/saml2/metadata', false);

        $this->assertEmpty($result['slo_url']);
    }

    /**
     * Test that generic KeyDescriptor (without use="signing") is used as fallback.
     *
     * When there's no KeyDescriptor[@use="signing"], the code should fall back
     * to KeyDescriptor without the @use attribute.
     */
    public function testMinimalMetadataGenericKeyDescriptorFallback(): void
    {
        $result = ($this->plugin)('https://idp-minimal.example.org/saml2/metadata', false);

        $this->assertNotEmpty(
            $result['sign_x509_certificates'],
            'Generic KeyDescriptor (without use="signing") should be picked up as fallback'
        );
    }

    /**
     * Test that encryption certificates are empty when not present.
     */
    public function testMinimalMetadataNoEncryptionCertificates(): void
    {
        $result = ($this->plugin)('https://idp-minimal.example.org/saml2/metadata', false);

        $this->assertEmpty($result['crypt_x509_certificates']);
    }

    // =========================================================================
    // Multiple certificates and whitespace handling
    // =========================================================================

    /**
     * Test that multiple signing certificates are all extracted.
     *
     * Shibboleth IdPs may use separate back-channel and front-channel
     * signing certificates.
     */
    public function testMultipleSigningCertificatesExtracted(): void
    {
        $result = ($this->plugin)('https://idp-multi.example.org/saml2/metadata', false);

        $this->assertNotNull($result);
        // The fixture has 2 different signing certificates.
        $this->assertCount(2, $result['sign_x509_certificates']);
    }

    /**
     * Test that certificates with tabs and spaces are cleaned properly.
     *
     * The code uses strtr() to remove tabs and spaces before formatCert().
     * The multi-cert fixture has leading tabs and spaces in base64.
     */
    public function testCertificateWhitespaceIsCleaned(): void
    {
        $result = ($this->plugin)('https://idp-multi.example.org/saml2/metadata', false);

        foreach ($result['sign_x509_certificates'] as $cert) {
            $this->assertStringNotContainsString("\t", $cert, 'Certificate should have no tabs');
            // After formatCert(), the cert has header/footer and newlines but no stray spaces.
            $lines = explode("\n", $cert);
            foreach ($lines as $line) {
                if ($line === '-----BEGIN CERTIFICATE-----' || $line === '-----END CERTIFICATE-----' || $line === '') {
                    continue;
                }
                $this->assertStringNotContainsString(' ', $line, 'Certificate base64 line should have no spaces');
            }
        }
    }

    /**
     * Test that duplicate certificates are deduplicated.
     *
     * If the same certificate appears in two KeyDescriptors, it should
     * appear only once in the result (array_unique is applied).
     */
    public function testDuplicateCertificatesAreDeduplicated(): void
    {
        $result = ($this->plugin)('https://idp-multi.example.org/saml2/metadata', false);

        $uniqueCerts = array_unique($result['sign_x509_certificates']);
        $this->assertCount(
            count($result['sign_x509_certificates']),
            $uniqueCerts,
            'Certificates should already be deduplicated'
        );
    }

    // =========================================================================
    // URN entity ID (not a URL)
    // =========================================================================

    /**
     * Test that a URN entity ID (e.g. urn:mace:...) is handled correctly.
     *
     * Some IdPs use URN-style entity IDs instead of URLs. The code prepends
     * "http://" for parse_url() to derive entity_short_id.
     */
    public function testUrnEntityIdIsParsed(): void
    {
        $result = ($this->plugin)('https://idp-urn.example.org/saml2/metadata', false);

        $this->assertNotNull($result);
        $this->assertSame('urn:mace:example.org:idp', $result['entity_id']);
    }

    /**
     * Test entity_short_id derivation from URN entity ID.
     *
     * For "urn:mace:example.org:idp", the code prepends "http://" giving
     * "http://urn:mace:example.org:idp". parse_url(PHP_URL_HOST) on that
     * returns false (invalid URL with non-numeric port), so the fallback
     * is the full entity ID.
     */
    public function testUrnEntityShortId(): void
    {
        $result = ($this->plugin)('https://idp-urn.example.org/saml2/metadata', false);

        // parse_url('http://urn:mace:example.org:idp', PHP_URL_HOST) returns
        // false because "mace" is not a valid port, so the code falls back
        // to the full entity ID. This is not ideal as a short_id.
        $entityShortId = $result['entity_short_id'];
        $this->assertNotEmpty($entityShortId);
        $this->assertSame('urn:mace:example.org:idp', $entityShortId);
    }

    /**
     * Test that host is derived from SSO URL even with URN entity ID.
     */
    public function testUrnEntityIdHostFromSsoUrl(): void
    {
        $result = ($this->plugin)('https://idp-urn.example.org/saml2/metadata', false);

        // Host should come from sso_url, not from the URN.
        $this->assertSame('login.example.org', $result['host']);
    }

    /**
     * Test that SLO URL is empty when not present (URN IdP).
     */
    public function testUrnEntityIdNoSloUrl(): void
    {
        $result = ($this->plugin)('https://idp-urn.example.org/saml2/metadata', false);

        $this->assertEmpty($result['slo_url']);
    }
}
