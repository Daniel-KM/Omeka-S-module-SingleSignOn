<?php declare(strict_types=1);

namespace SingleSignOn\Mvc\Controller\Plugin;

use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class IdpMetadata extends AbstractPlugin
{
    /**
     * Get metadata from an idp url.
     *
     *  Metadata are: entity id, sso url, slo url and x509 certificate.
     */
    public function __invoke(?string $idpUrl, bool $useMessenger = false): ?array
    {
        if ($useMessenger) {
            /** @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
            $messenger = $this->getController()->messenger();
        }

        if (!filter_var($idpUrl, FILTER_VALIDATE_URL)) {
            if ($useMessenger) {
                $message = new \Omeka\Stdlib\Message(
                    'The IdP url "%s" is not valid.', // @translate
                    $idpUrl
                );
                $messenger->addError($message);
            }
            return null;
        }

        $idpString = file_get_contents($idpUrl);
        if (!$idpString) {
            if ($useMessenger) {
                $message = new \Omeka\Stdlib\Message(
                    'The IdP url "%s" does not return any metadata.', // @translate
                    $idpUrl
                );
                $messenger->addError($message);
            }
            return null;
        }

        /** @var \SimpleXMLElement $idpXml */
        $idpXml = @simplexml_load_string($idpString);
        if (!$idpXml) {
            if ($useMessenger) {
                $message = new \Omeka\Stdlib\Message(
                    'The IdP url "%s" does not return valid xml metadata.', // @translate
                    $idpUrl
                );
                $messenger->addError($message);
            }
            return null;
        }

        $entityId = (string) ($idpXml['entityID'] ?? parse_url($idpUrl, PHP_URL_HOST));

        // The One-Login library supports "Redirect" only.
        $ssoUrl = (string) ($idpXml->xpath('//IDPSSODescriptor/SingleSignOnService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');
        $sloUrl = (string) ($idpXml->xpath('//IDPSSODescriptor/SingleLogoutService[@Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location')[0] ?? '');

        // Prefer the certificate used for encryption, not signing.
        $x509Certificate = (string) ($idpXml->xpath('//IDPSSODescriptor/KeyDescriptor[@use = "encryption"]/KeyInfo/X509Data/X509Certificate[1]')[0] ?? '')
            ?: (string) ($idpXml->xpath('//IDPSSODescriptor/KeyDescriptor/KeyInfo/X509Data/X509Certificate[1]')[0] ?? '');
        // The xml may add tabulations and spaces, to be removed.
        $x509Certificate = str_replace(["\t", ' '], '', $x509Certificate);

        return [
            'idp_metadata_url' => $idpUrl,
            'idp_entity_id' => $entityId,
            'idp_sso_url' => $ssoUrl,
            'idp_slo_url' => $sloUrl,
            'idp_x509_certificate' => $x509Certificate,
        ];
    }
}
