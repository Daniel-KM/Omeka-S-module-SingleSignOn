<?php declare(strict_types=1);

namespace SingleSignOn\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Mvc\Exception;
use Laminas\Session\Container;
use Omeka\Entity\User;
use Omeka\Mvc\Exception\RuntimeException;
use Omeka\Stdlib\Message;
use OneLogin\Saml2\Auth as SamlAuth;
use OneLogin\Saml2\Error as SamlError;
use OneLogin\Saml2\Settings as SamlSettings;

class SsoController extends AbstractActionController
{
    /**
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @var AuthenticationService
     */
    protected $authentication;

    /**
     * @var array
     */
    protected $attributesMapCanonical = [
        'urn:oid:0.9.2342.19200300.100.1.3' => 'email',
        'urn:oid:2.16.840.1.113730.3.1.241' => 'name',
        'https://samltest.id/attributes/role' => 'role',
    ];

    public function __construct(
        EntityManager $entityManager,
        AuthenticationService $authenticationService
    ) {
        $this->entityManager = $entityManager;
        $this->authentication = $authenticationService;
    }

    public function metadataAction()
    {
        $configSso = $this->validConfigSso(true);
        $samlSettings = new SamlSettings($configSso, true);
        $metadata = $samlSettings->getSPMetadata();

        /** @var \Laminas\Http\Response $response */
        $response = $this->getResponse();
        $response
            ->setContent($metadata)
            ->getHeaders()
            ->addHeaderLine('Content-Type', 'text/xml');
        return $response;
    }

    /**
     * @see \Omeka\Controller\LoginController::login()
     */
    public function loginAction()
    {
        $user = $this->authentication->getIdentity();
        $redirectUrl = $this->redirectUrl();
        if ($user) {
            return $this->redirect()->toUrl($redirectUrl);
        }

        $configSso = $this->validConfigSso(true);
        $samlAuth = new SamlAuth($configSso);

        // Redirect to external IdP.
        return $samlAuth->login($redirectUrl);
    }

    /**
     * Log in on the IdP via the ACS (assertion consumer service).
     */
    public function acsAction()
    {
        $redirectUrl = $this->redirectUrl();

        $user = $this->authentication->getIdentity();
        if ($user) {
            return $this->redirect()->toUrl($redirectUrl);
        }

        $configSso = $this->validConfigSso(true);
        $samlAuth = new SamlAuth($configSso);

        $samlAuth->processResponse();
        $errors = $samlAuth->getErrors();
        if ($errors) {
            $lastErrorReason = $samlAuth->getLastErrorReason();
            if ($lastErrorReason) {
                $message = new Message(
                    'Single sign-on failed: %1$s. %2$s', // @translate
                    implode(', ', $errors),
                    $lastErrorReason
                );
            } else {
                $message = new Message(
                    'Single sign-on failed: %s', // @translate
                    implode(', ', $errors)
                );
            }
            $this->messenger()->addError($message);
            $this->logger()->err($message);
            // Since this is a config or idp error, redirect to local login.
            return $this->redirect()->toRoute('login');
        }

        $nameId = $samlAuth->getNameId();
        $samlAttributesFriendly = $samlAuth->getAttributesWithFriendlyName();
        $samlAttributesCanonical = $samlAuth->getAttributes();

        // The map is already checked.
        $attributesMap = $this->settings()->get('singlesignon_attributes_map', []);
        $email = $samlAttributesFriendly[array_search('email', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('email', $this->attributesMapCanonical)][0]
            ?? null;
        if (!$email && strpos($nameId, '@')) {
            $email = $nameId;
        }

        if (!$email) {
            $message = new Message('No email provided to log in or register.'); // @translate
            $this->messenger()->addError($message);
            $message = new Message('No email provided or mapped. Available canonical attributes for this IdP: %1$s. Available friendly attributes for this IdP: %2$s.', // @translate
                implode(', ', array_keys($samlAttributesCanonical)),
                implode(', ', array_keys($samlAttributesFriendly))
            );
            $this->logger()->err($message);
            // Since this is a config or idp error, redirect to local login.
            return $this->redirect()->toRoute('login');
        }

        $name = $samlAttributesFriendly[array_search('name', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('name', $this->attributesMapCanonical)][0]
            ?? null;
        $role = $samlAttributesFriendly[array_search('role', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('role', $this->attributesMapCanonical)][0]
            ?? 'guest';

        $user = $this->entityManager
            ->getRepository(\Omeka\Entity\User::class)
            ->findOneBy(['email' => $email]);

        if (empty($user)) {
            if (!$name) {
                $message = new Message('No name provided to register a new user.'); // @translate
                $this->messenger()->addError($message);
                $message = new Message('No name provided or mapped. Available canonical attributes for this IdP: %1$s. Available friendly attributes for this IdP: %2$s.', // @translate
                    implode(', ', array_keys($samlAttributesCanonical)),
                    implode(', ', array_keys($samlAttributesFriendly))
                );
                $this->logger()->err($message);
                // Since this is a config or idp error, redirect to local login.
                return $this->redirect()->toRoute('login');
            }

            $user = new User();
            $user->setEmail($email);
            $user->setName($name);
            $user->setRole($role);
            $user->setIsActive(true);

            $this->entityManager->persist($user);
            $this->entityManager->flush();
        } elseif (!$user->isActive()) {
            $message = new Message('User "%s" is inactive.', $email); // @translate
            $this->messenger()->addError($message);
            $this->logger()->warn($message);
            // Since this is a non-authorized user, return to redirect url.
            return $this->redirect()->toUrl($redirectUrl);
        } else {
            $update = false;
            if ($name && $name !== $user->getName()) {
                $update = true;
                $user->setName($name);
            }
            /* Update role via admin interface only for now.
            if ($role && $role !== $user->getRole) {
                $update = true;
                $user->setRole($role);
            }
            */
            if ($update) {
                $this->entityManager->persist($user);
                $this->entityManager->flush();
            }
        }

        $sessionManager = Container::getDefaultManager();
        $sessionManager->regenerateId();

        $adapter = $this->authentication->getAdapter();
        $adapter->setIdentity($user->getEmail());

        // Unlike module Shibboleth, the AuthenticationService isn't overridden,
        // so the authentication cannot be check directly in the laminas way.
        // So write it directly.
        $this->authentication->getStorage()->write($user);
        // A useless check.
        $user = $this->authentication->getIdentity();

        $this->messenger()->addSuccess('Successfully logged in.'); // @translate

        $eventManager = $this->getEventManager();
        $eventManager->trigger('user.login', $user);

        // The redirect url is refreshed because user is authenticated.
        $redirectUrl = $this->redirectUrl();
        return $this->redirect()->toUrl($redirectUrl);
    }

    protected function redirectUrl(): string
    {
        $redirectUrl = $this->params()->fromQuery('redirect_url') ?: null;
        if ($redirectUrl) {
            return $redirectUrl;
        }

        $session = Container::getDefaultManager()->getStorage();
        $redirectUrl = $session->offsetGet('redirect_url');
        if ($redirectUrl) {
            return $redirectUrl;
        }

        $user = $this->authentication->getIdentity();
        return $user && $this->userIsAllowed('Omeka\Controller\Admin\Index', 'index')
            ? $this->url()->fromRoute('admin')
            :  $this->url()->fromRoute('top');
    }

    protected function validConfigSso(bool $throw = false): ?array
    {
        try {
            $configSso = $this->configSso();
            new SamlSettings($configSso);
        } catch (SamlError $e) {
            $message = new Message('SSO service has an error in configuration: %s', $e); // @translate
            $this->logger()->err($message);
            if (!$throw) {
                return null;
            }
            $message = new Message(
                'SSO service is not available. Ask admin to config it.' // @translate
            );
            throw new RuntimeException((string) $message);
        } catch (\Exception $e) {
            $this->logger()->err('SSO service is unavailable.'); // @translate
            if (!$throw) {
                return null;
            }
            $message = new Message(
                'SSO service is unavailable. Ask admin to config it.' // @translate
            );
            throw new \Omeka\Mvc\Exception\RuntimeException((string) $message);
        }

        unset($configSso['sp']['singleLogoutService']);

        return $configSso;
    }

    protected function configSso(): array
    {
        $url = $this->url();
        $settings = $this->settings();

        $baseUrlSso = rtrim($url->fromRoute('sso', [], ['force_canonical' => true]), '/');

        /**
         * @see vendor/onelogin/php-saml/settings_example.php
         * @see vendor/onelogin/php-saml/advanced_settings_example.php
         */
        return $settings = [
            // If 'strict' is True, then the PHP Toolkit will reject unsigned
            // or unencrypted messages if it expects them signed or encrypted
            // Also will reject the messages if not strictly follow the SAML
            // standard: Destination, NameId, Conditions ... are validated too.
            'strict' => true,

            // Enable debug mode (to print errors)
            'debug' => false,

            // Set a BaseURL to be used instead of try to guess
            // the BaseURL of the view that process the SAML Message.
            // Ex. http://sp.example.com/
            //     http://example.com/sp/
            'baseurl' => $baseUrlSso,

            // Service Provider Data that we are deploying
            'sp' => [

                // Identifier of the SP entity  (must be a URI)
                'entityId' => $baseUrlSso,

                // Specifies info about where and how the <AuthnResponse> message MUST be
                // returned to the requester, in this case our SP.
                'assertionConsumerService' => [
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => $baseUrlSso . '/acs',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-POST binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                ],

                // If you need to specify requested attributes, set a
                // attributeConsumingService. nameFormat, attributeValue and
                // friendlyName can be omitted. Otherwise remove this section.
                /*
                'attributeConsumingService' => [
                    'serviceName' => 'SP test',
                    'serviceDescription' => 'Test Service',
                    'requestedAttributes' => [
                        [
                            'name' => '',
                            'isRequired' => false,
                            'nameFormat' => '',
                            'friendlyName' => '',
                            'attributeValue' => '',
                        ],
                    ],
                ],
                */

                // Specifies info about where and how the <Logout Response> message MUST be
                // returned to the requester, in this case our SP.
                'singleLogoutService' => [
                    // URL Location where the <Response> from the IdP will be returned
                    'url' => $baseUrlSso . '/sls',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],

                // Specifies constraints on the name identifier to be used to
                // represent the requested subject.
                // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',

                // Usually x509cert and privateKey of the SP are provided by files placed at
                // the certs folder. But we can also provide them with the following parameters
                'x509cert' => '',
                'privateKey' => '',

                /*
                 * Key rollover
                 * If you plan to update the SP x509cert and privateKey
                 * you can define here the new x509cert and it will be
                 * published on the SP metadata so Identity Providers can
                 * read them and get ready for rollover.
                 */
                // 'x509certNew' => '',
            ],

            // Identity Provider Data that we want connect with our SP
            'idp' => [

                // Identifier of the IdP entity  (must be a URI)
                'entityId' => $settings->get('singlesignon_idp_entity_id', ''),

                // SSO endpoint info of the IdP. (Authentication Request protocol)
                'singleSignOnService' => [
                    // URL Target of the IdP where the SP will send the Authentication Request Message
                    'url' => $settings->get('singlesignon_idp_sso_url', ''),
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],

                // SLO endpoint info of the IdP.
                'singleLogoutService' => [
                    // URL Location of the IdP where the SP will send the SLO Request
                    'url' => $settings->get('singlesignon_idp_slo_url', ''),
                    // URL location of the IdP where the SP SLO Response will be sent (ResponseLocation)
                    // if not set, url for the SLO Request will be used
                    'responseUrl' => '',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],

                // Public x509 certificate of the IdP
                'x509cert' => $settings->get('singlesignon_idp_x509_certificate', ''),

                /*
                 *  Instead of use the whole x509cert you can use a fingerprint in
                 *  order to validate the SAMLResponse, but we don't recommend to use
                 *  that method on production since is exploitable by a collision
                 *  attack.
                 *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it,
                 *  or add for example the -sha256 , -sha384 or -sha512 parameter)
                 *
                 *  If a fingerprint is provided, then the certFingerprintAlgorithm is required in order to
                 *  let the toolkit know which Algorithm was used. Possible values: sha1, sha256, sha384 or sha512
                 *  'sha1' is the default value.
                 */
                // 'certFingerprint' => '',
                // 'certFingerprintAlgorithm' => 'sha1',

                /* In some scenarios the IdP uses different certificates for
                 * signing/encryption, or is under key rollover phase and more
                 * than one certificate is published on IdP metadata.
                 * In order to handle that the toolkit offers that parameter.
                 * (when used, 'x509cert' and 'certFingerprint' values are
                 * ignored).
                 */
                // 'x509certMulti' => [
                //      'signing' => [
                //          0 => '<cert1-string>',
                //      ],
                //      'encryption' => [
                //          0 => '<cert2-string>',
                //      ],
                // ],
            ],

            // Advanced settings.

            [

                // Compression settings
                // Handle if the getRequest/getResponse methods will return the Request/Response deflated.
                // But if we provide a $deflate boolean parameter to the getRequest or getResponse
                // method it will have priority over the compression settings.
                'compress' => [
                    'requests' => true,
                    'responses' => true
                ],

                // Security settings
                'security' => [

                    /** signatures and encryptions offered */

                    // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
                    // will be encrypted.
                    'nameIdEncrypted' => false,

                    // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
                    // will be signed.              [The Metadata of the SP will offer this info]
                    'authnRequestsSigned' => false,

                    // Indicates whether the <samlp:logoutRequest> messages sent by this SP
                    // will be signed.
                    'logoutRequestSigned' => false,

                    // Indicates whether the <samlp:logoutResponse> messages sent by this SP
                    // will be signed.
                    'logoutResponseSigned' => false,

                    /* Sign the Metadata
                     False || True (use sp certs) || array (
                     keyFileName => 'metadata.key',
                     certFileName => 'metadata.crt'
                     )
                     */
                    'signMetadata' => false,

                    /** signatures and encryptions required **/

                    // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
                    // <samlp:LogoutResponse> elements received by this SP to be signed.
                    'wantMessagesSigned' => false,

                    // Indicates a requirement for the <saml:Assertion> elements received by
                    // this SP to be encrypted.
                    'wantAssertionsEncrypted' => false,

                    // Indicates a requirement for the <saml:Assertion> elements received by
                    // this SP to be signed.        [The Metadata of the SP will offer this info]
                    'wantAssertionsSigned' => false,

                    // Indicates a requirement for the NameID element on the SAMLResponse received
                    // by this SP to be present.
                    'wantNameId' => true,

                    // Indicates a requirement for the NameID received by
                    // this SP to be encrypted.
                    'wantNameIdEncrypted' => false,

                    // Authentication context.
                    // Set to false and no AuthContext will be sent in the AuthNRequest,
                    // Set true or don't present this parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
                    // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
                    'requestedAuthnContext' => false,

                    // Allows the authn comparison parameter to be set, defaults to 'exact' if
                    // the setting is not present.
                    'requestedAuthnContextComparison' => 'exact',

                    // Indicates if the SP will validate all received xmls.
                    // (In order to validate the xml, 'strict' and 'wantXMLValidation' must be true).
                    'wantXMLValidation' => true,

                    // If true, SAMLResponses with an empty value at its Destination
                    // attribute will not be rejected for this fact.
                    'relaxDestinationValidation' => false,

                    // Algorithm that the toolkit will use on signing process. Options:
                    //    'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
                    //    'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
                    //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                    //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
                    //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
                    // Notice that sha1 is a deprecated algorithm and should not be used
                    'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

                    // Algorithm that the toolkit will use on digest process. Options:
                    //    'http://www.w3.org/2000/09/xmldsig#sha1'
                    //    'http://www.w3.org/2001/04/xmlenc#sha256'
                    //    'http://www.w3.org/2001/04/xmldsig-more#sha384'
                    //    'http://www.w3.org/2001/04/xmlenc#sha512'
                    // Notice that sha1 is a deprecated algorithm and should not be used
                    'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',

                    // ADFS URL-Encodes SAML data as lowercase, and the toolkit by default uses
                    // uppercase. Turn it True for ADFS compatibility on signature verification
                    'lowercaseUrlencoding' => false,
                ],

                // Contact information template, it is recommended to suply a technical and support contacts
                'contactPerson' => [
                    'technical' => [
                        'givenName' => '',
                        'emailAddress' => ''
                    ],
                    'support' => [
                        'givenName' => '',
                        'emailAddress' => ''
                    ],
                ],

                // Organization information template, the info in en_US lang is recomended, add more if required
                'organization' => [
                    'en-US' => [
                        'name' => '',
                        'displayname' => '',
                        'url' => ''
                    ],
                ],
            ],

            /*
            // Interoperable SAML 2.0 Web Browser SSO Profile [saml2int]   http://saml2int.org/profile/current
            'authnRequestsSigned' => false,    // SP SHOULD NOT sign the <samlp:AuthnRequest>,
            // MUST NOT assume that the IdP validates the sign
            'wantAssertionsSigned' => true,
            'wantAssertionsEncrypted' => true, // MUST be enabled if SSL/HTTPs is disabled
            'wantNameIdEncrypted' => false,
            */

        ];
    }
}