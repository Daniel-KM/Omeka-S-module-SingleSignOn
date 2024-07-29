<?php declare(strict_types=1);

namespace SingleSignOn\Mvc\Controller\Plugin;

use Common\Stdlib\PsrMessage;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use SimpleXMLElement;

class IdpMetadata extends AbstractPlugin
{
    /**
     * Get metadata from an idp url.
     *
     * Metadata are: entity id, sso url, slo url and x509 certificate.
     */
    public function __invoke(?string $idpUrl, bool $useMessenger = false): ?array
    {
        $idpUrl = trim((string) $idpUrl);
        if (!$idpUrl) {
            return null;
        }

        if ($useMessenger) {
            /** @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
            $messenger = $this->getController()->messenger();
        }

        if (!filter_var($idpUrl, FILTER_VALIDATE_URL)) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The IdP url "{url}" is not valid.', // @translate
                    ['url' => $idpUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        $idpString = file_get_contents($idpUrl);
        if (!$idpString) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The IdP url {url} does not return any metadata.', // @translate
                    ['url' => $idpUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        /** @var \SimpleXMLElement $xml */
        $xml = @simplexml_load_string($idpString);
        if (!$xml) {
            if ($useMessenger) {
                $message = new PsrMessage(
                    'The IdP url {url} does not return valid xml metadata.', // @translate
                    ['url' => $idpUrl]
                );
                $messenger->addError($message);
            }
            return null;
        }

        /**
         * @see \SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata
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

        $entityId = (string) ($xml['samlmetadata:entityID']
            ?? $xml['entityID']
            ?? parse_url($idpUrl, PHP_URL_HOST));
        $entityId = $entityId ?: '';

        if ($namespaces) {
            $entityName = (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:Organization/samlmetadata:OrganizationName[1]')[0] ?? '')
                ?: (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:IDPSSODescriptor/samlmetadata:Extensions/mdui:UIInfo/mdui:DisplayName[1]')[0] ?? '');
            // The One-Login library supports "Redirect" only.
            $ssoUrl = (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:IDPSSODescriptor/samlmetadata:SingleSignOnService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
            $sloUrl = (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:IDPSSODescriptor/samlmetadata:SingleLogoutService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
            // Prefer the certificate used for encryption, not signing.
            $x509Certificate = (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:IDPSSODescriptor/samlmetadata:KeyDescriptor[@use = "encryption"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '')
                ?: (string) ($registerXpathNamespaces($xml)->xpath('//samlmetadata:IDPSSODescriptor/samlmetadata:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate[1]')[0] ?? '');
        } else {
            $entityName = (string) ($xml->xpath('//Organization/OrganizationName[1]')[0] ?? '')
                ?: (string) ($xml->xpath('//IDPSSODescriptor/Extensions/UIInfo/DisplayName[1]')[0] ?? '');
            // The One-Login library supports "Redirect" only.
            $ssoUrl = (string) ($xml->xpath('//IDPSSODescriptor/SingleSignOnService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
            $sloUrl = (string) ($xml->xpath('//IDPSSODescriptor/SingleLogoutService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
            // Prefer the certificate used for encryption, not signing.
            $x509Certificate = (string) ($xml->xpath('//IDPSSODescriptor/KeyDescriptor[@use = "encryption"]/KeyInfo/X509Data/X509Certificate[1]')[0] ?? '')
                ?: (string) ($xml->xpath('//IDPSSODescriptor/KeyDescriptor/KeyInfo/X509Data/X509Certificate[1]')[0] ?? '');
        }

        return [
            'idp_metadata_url' => $idpUrl,
            'idp_entity_id' => trim($entityId),
            'idp_entity_name' => trim($entityName),
            'idp_sso_url' => trim($ssoUrl),
            'idp_slo_url' => trim($sloUrl),
            // The xml may add tabulations and spaces, to be removed.
            'idp_x509_certificate' => trim(str_replace(["\t", ' '], '', $x509Certificate)),
            'idp_date' => (new \DateTime('now'))->format(\DateTime::ISO8601),
        ];
    }
}
