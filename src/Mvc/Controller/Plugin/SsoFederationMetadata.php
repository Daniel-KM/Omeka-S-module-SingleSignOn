<?php declare(strict_types=1);

namespace SingleSignOn\Mvc\Controller\Plugin;

use Common\Stdlib\PsrMessage;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use SimpleXMLElement;

class SsoFederationMetadata extends AbstractPlugin
{
    /**
     * Get metadata from a federation url.
     *
     * Metadata are: entity id, sso url, slo url and x509 certificate.
     */
    public function __invoke(?string $federationUrl, bool $useMessenger = false): ?array
    {
        $federationUrl = trim((string) $federationUrl);
        if (!$federationUrl) {
            return null;
        }

        if ($useMessenger) {
            /** @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
            $messenger = $this->getController()->messenger();
        }

        if (!filter_var($federationUrl, FILTER_VALIDATE_URL)) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The federation url "{url}" is not valid.', // @translate
                    ['url' => $federationUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        $federationString = file_get_contents($federationUrl);
        if (!$federationString) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The federation url {url} does not return any metadata.', // @translate
                    ['url' => $federationUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        /** @var \SimpleXMLElement $xml */
        $xml = @simplexml_load_string($federationString);
        if (!$xml) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The federation url {url} does not return valid xml metadata.', // @translate
                    ['url' => $federationUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        /**
         * @see \SingleSignOn\Mvc\Controller\Plugin\IdpMetadata
         */

        $namespaces = $xml->getDocNamespaces();

        // Register xpath should be done for each call. So not very usable.
        $registerXpathNamespaces = function (SimpleXMLElement $xml): SimpleXMLElement {
            $xml->registerXPathNamespace('', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $xml->registerXPathNamespace('samlmetadata', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $xml->registerXPathNamespace('samlassertion', 'urn:oasis:names:tc:SAML:2.0:assertion');
            $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
            $xml->registerXPathNamespace('mdui', 'urn:oasis:names:tc:SAML:metadata:ui');
            $xml->registerXPathNamespace('req-attr', 'urn:oasis:names:tc:SAML:protocol:ext:req-attr');
            $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
            $xml->registerXPathNamespace('shibmd', 'urn:mace:shibboleth:metadata:1.0');
            $xml->registerXPathNamespace('xml', 'http://www.w3.org/XML/1998/namespace');
            $xml->registerXPathNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
            return $xml;
        };

        $list = [];

        $date = (new \DateTime('now'))->format(\DateTime::ISO8601);
        if ($namespaces) {
            $entityIds = (array) ($registerXpathNamespaces($xml)->xpath('/md:EntitiesDescriptor/md:EntityDescriptor/@entityID') ?? []);
            foreach ($entityIds as $entityId) {
                $entityId = trim((string) $entityId);
                $baseXpath = sprintf('/md:EntitiesDescriptor/md:EntityDescriptor[@entityID="%s"]', $entityId);
                $entityName = (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:Organization/md:OrganizationName[1]')[0] ?? '')
                    ?: (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[1]')[0] ?? '');
                // The One-Login library supports "Redirect" only.
                $ssoUrl = (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:IDPSSODescriptor/md:SingleSignOnService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
                $sloUrl = (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:IDPSSODescriptor/md:SingleLogoutService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
                // Prefer the certificate used for encryption, not signing.
                $x509Certificate = (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:IDPSSODescriptor/md:KeyDescriptor[@use = "encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '')
                    ?: (string) ($registerXpathNamespaces($xml)->xpath($baseXpath . '/md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '');
                $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
                $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;
                $list[$idpName] = [
                    'federation_url' => $federationUrl,
                    'idp_metadata_url' => null,
                    'idp_entity_id' => $entityId,
                    'idp_entity_name' => trim($entityName),
                    'idp_sso_url' => trim($ssoUrl),
                    'idp_slo_url' => trim($sloUrl),
                    // The xml may add tabulations and spaces, to be removed.
                    'idp_x509_certificate' => trim(str_replace(["\t", ' '], '', $x509Certificate)),
                    'idp_date' => $date,
                ];
            }
        } else {
            $entityIds = (array) ($xml->xpath('/EntitiesDescriptor/EntityDescriptor/@entityID') ?? []);
            foreach ($entityIds as $entityId) {
                $entityId = trim((string) $entityId);
                $baseXpath = sprintf('/EntitiesDescriptor/EntityDescriptor[@entityID="%s"]', $entityId);
                $entityName = (string) ($xml->xpath($baseXpath . '/Organization/OrganizationName[1]')[0] ?? '')
                    ?: (string) ($xml->xpath($baseXpath . '/IDPSSODescriptor/Extensions/UIInfo/mdui:DisplayName[1]')[0] ?? '');
                // The One-Login library supports "Redirect" only.
                $ssoUrl = (string) ($xml->xpath($baseXpath . '/IDPSSODescriptor/SingleSignOnService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
                $sloUrl = (string) ($xml->xpath($baseXpath . '/IDPSSODescriptor/SingleLogoutService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
                // Prefer the certificate used for encryption, not signing.
                $x509Certificate = (string) ($xml->xpath($baseXpath . '/IDPSSODescriptor/KeyDescriptor[@use = "encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '')
                    ?: (string) ($xml->xpath($baseXpath . '/IDPSSODescriptor/KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '');
                $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
                $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;
                $list[$idpName] = [
                    'federation_url' => $federationUrl,
                    'idp_metadata_url' => null,
                    'idp_entity_id' => $entityId,
                    'idp_entity_name' => trim($entityName),
                    'idp_sso_url' => trim($ssoUrl),
                    'idp_slo_url' => trim($sloUrl),
                    // The xml may add tabulations and spaces, to be removed.
                    'idp_x509_certificate' => trim(str_replace(["\t", ' '], '', $x509Certificate)),
                    'idp_date' => $date,
                ];
            }
        }

        return $list;
    }
}