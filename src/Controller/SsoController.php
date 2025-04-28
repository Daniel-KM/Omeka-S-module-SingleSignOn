<?php declare(strict_types=1);

namespace SingleSignOn\Controller;

use Common\Stdlib\PsrMessage;
use DateTime;
use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Client as HttpClient;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container;
use Omeka\Entity\User;
use Omeka\Mvc\Exception\RuntimeException;
use Omeka\Permissions\Acl;
use OneLogin\Saml2\Auth as SamlAuth;
use OneLogin\Saml2\Error as SamlError;
use OneLogin\Saml2\Settings as SamlSettings;
use SimpleXMLElement;

class SsoController extends AbstractActionController
{
    /**
     * @var \Omeka\Permissions\Acl
     */
    protected $acl;

    /**
     * @var \Laminas\Authentication\AuthenticationService
     */
    protected $authentication;

    /**
     * @var \Doctrine\ORM\EntityManager
     */
    protected $entityManager;

    /**
     * @var \Laminas\Http\Client
     */
    protected $httpClient;

    /**
     * @var array
     */
    protected $attributesMapCanonical = [
        'urn:oid:0.9.2342.19200300.100.1.3' => 'email',
        'urn:oid:2.16.840.1.113730.3.1.241' => 'name',
        'https://samltest.id/attributes/role' => 'role',
    ];

    /**
     * @var array
     */
    protected $providerData = [
        'metadata_url' => '',
        'entity_id' => '',
        'entity_name' => '',
        'entity_short_id' => '',
        'host' => '',
        'sso_url' => '',
        'slo_url' => '',
        'sign_x509_certificates' => [],
        'crypt_x509_certificates' => [],
        'date' => '',
        'attributes_map' => [],
        'roles_map' => [],
        'user_settings' => [],
        'metadata_update_mode' => 'auto',
    ];

    public function __construct(
        Acl $acl,
        AuthenticationService $authenticationService,
        EntityManager $entityManager,
        HttpClient $httpClient
    ) {
        $this->acl = $acl;
        $this->authentication = $authenticationService;
        $this->entityManager = $entityManager;
        $this->httpClient = $httpClient;
    }

    /**
     * Get the metadata of the sp or any managed idp set in route.
     */
    public function metadataAction()
    {
        // When the idp is set, it means to get its metadata.
        $idpName = $this->params()->fromRoute('idp');

        $isSp = empty($idpName);
        if ($isSp) {
            // Check for metadata of the current sp (option true of SamlSettings).
            $configSso = $this->validConfigSso(null, false) ?: [];
            $samlSettings = new SamlSettings($configSso, true);
            $settings = $this->settings();
            $spCryptX509cert = trim($settings->get('singlesignon_sp_crypt_x509_certificate') ?: '');
            $spCryptPrivateKey = trim($settings->get('singlesignon_sp_crypt_x509_private_key') ?: '');
            $alwaysPublishEncryptionCert = $spCryptX509cert && $spCryptPrivateKey;
            $metadata = $samlSettings->getSPMetadata($alwaysPublishEncryptionCert);
        } else {
            $metadata = $this->idpMetadataXml($idpName);
            if (!$metadata) {
                $redirectUrl = $this->redirectUrl();
                return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
            }
        }

        // Some idps don't manage namespaces, so remove them in basic mode.
        $xmlMode = $this->settings()->get('singlesignon_sp_metadata_mode', 'standard');
        if ($isSp && $xmlMode === 'basic') {
            // To remove namespaces is pretty complex in php, so use a quick
            // hack for now.
            $replace = [
                'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"' => '',
                '<md:' => '<',
                '</md:' => '</',
                '<ds:' => '<',
                '</ds:' => '</',
            ];
            $metadata = str_replace(array_keys($replace), array_values($replace), $metadata);
        }

        /**
         * @var \Laminas\Http\Response $response
         * @var \Laminas\Http\Headers $headers
         */
        $response = $this->getResponse();
        $headers = $response->getHeaders();

        $headers
            // Don't use mb_strlen() here.
            ->addHeaderLine('Content-Length', strlen($metadata));

        $contentType = $this->settings()->get('singlesignon_sp_metadata_content_type', 'application/samlmetadata+xml');
        switch ($contentType) {
            default:
            case 'saml':
                $headers
                    ->addHeaderLine('Content-Type', 'application/samlmetadata+xml');
                break;
            case 'xml':
                $headers
                    ->addHeaderLine('Content-Type', 'application/xml');
                break;
        }

        $contentDisposition = $this->settings()->get('singlesignon_sp_metadata_disposition', 'inline');
        switch ($contentDisposition) {
            default:
            case 'inline':
                $headers
                    ->addHeaderLine('Content-Disposition', 'inline');
                break;
            case 'attachment':
                $headers
                    ->addHeaderLine('Content-Disposition', 'attachment; filename="metadata.xml');
                break;
            case 'undefined':
                break;
        }

        $response
            ->setContent($metadata);
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

        $idpName = $this->params()->fromRoute('idp')
            // The select on login page uses a form "get".
            ?: $this->params()->fromQuery('idp')
            // But allow post for other implementations.
            ?: $this->params()->fromPost('idp');

        $idp = $idpName
            ? $this->idpData($idpName, true)
            : $this->providerData;
        if (!$idp['entity_id']) {
            $this->messenger()->addError(new PsrMessage('No IdP with this name.')); // @translate
            return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
        }

        $idpEntityId = $idp['entity_id'];
        $configSso = $this->validConfigSso($idpEntityId, true);

        if (empty($configSso['sp']['assertionConsumerService'])) {
            $this->messenger()->addWarning(new PsrMessage('Single sign-on is disabled.')); // @translate
            return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
        }

        $samlAuth = new SamlAuth($configSso);

        // Redirect to external IdP.
        return $samlAuth->login($redirectUrl);
    }

    public function logoutAction()
    {
        $redirectUrl = $this->params()->fromQuery('redirect_url')
            ?: $this->redirect()->toRoute('top');

        $user = $this->authentication->getIdentity();
        if (!$user) {
            return $this->redirect()->toUrl($redirectUrl);
        }

        $this->authentication->clearIdentity();

        // Don't check for a valid idp: logout in all cases.
        $idpName = $this->params()->fromRoute('idp');

        $configSso = $this->validConfigSso($idpName, true);
        $isSlsAvailable = !empty($configSso['sp']['singleLogoutService']);
        if ($isSlsAvailable) {
            $samlAuth = new SamlAuth($configSso);
        }

        $sessionManager = Container::getDefaultManager();

        $eventManager = $this->getEventManager();
        $eventManager->trigger('user.logout');

        $session = $sessionManager->getStorage();

        if (!$isSlsAvailable) {
            $sessionManager->destroy();
            return $this->redirect()->toUrl($redirectUrl);
        }

        $result = $samlAuth->logout(
            $redirectUrl,
            [],
            $session->offsetGet('saml_name_id'),
            $session->offsetGet('saml_session_index'),
            false,
            $session->offsetGet('saml_name_id_format'),
            $session->offsetGet('saml_name_id_name_qualifier')
        );

        $sessionManager->destroy();
        return $result;
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

        $idpName = $this->params()->fromRoute('idp')
            ?: $this->idpNameFromRequest();

        $idp = $idpName
            ? $this->idpData($idpName, true)
            : $this->providerData;
        if (!$idp['entity_id']) {
            $this->messenger()->addError(new PsrMessage('No IdP with this name.')); // @translate
            return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
        }

        $idpEntityId = $idp['entity_id'];

        $configSso = $this->validConfigSso($idpEntityId, true);
        if (empty($configSso['sp']['assertionConsumerService'])) {
            $this->messenger()->addWarning(new PsrMessage('Single sign-on is disabled.')); // @translate
            return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
        }

        $samlAuth = new SamlAuth($configSso);

        $samlAuth->processResponse();
        $errors = $samlAuth->getErrors();
        if ($errors) {
            $lastErrorReason = $samlAuth->getLastErrorReason();
            if ($lastErrorReason) {
                $message = new PsrMessage(
                    'Single sign-on failed: {errors}. {error_last}', // @translate
                    [
                        'errors' => implode(', ', $errors),
                        'error_last' => $lastErrorReason,
                    ]
                );
            } else {
                $message = new PsrMessage(
                    'Single sign-on failed: {errors}', // @translate
                    ['errors' => implode(', ', $errors)]
                );
            }
            $this->messenger()->addError($message);
            $this->logger()->err($message->getMessage(), $message->getContext());
            // Since this is a config or idp error, redirect to local login.
            return $this->redirect()->toRoute('login');
        }

        // Name id is a crypted name, not the real name.
        $nameId = $samlAuth->getNameId();
        $samlAttributesFriendly = $samlAuth->getAttributesWithFriendlyName();
        $samlAttributesCanonical = $samlAuth->getAttributes();

        // The map is already checked.
        $attributesMap = $idp['attributes_map'];
        $email = $samlAttributesFriendly[array_search('email', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('email', $this->attributesMapCanonical)][0]
            ?? $samlAttributesCanonical[array_search('email', $attributesMap)][0]
            ?? null;
        if (!$email && strpos($nameId, '@')) {
            $email = $nameId;
        }

        if (!$email) {
            $message = new PsrMessage('No email provided to log in or register.'); // @translate
            $this->messenger()->addError($message);
            $message = new PsrMessage(
                'No email provided or mapped. Available canonical attributes for this IdP: {keys}. Available friendly attributes for this IdP: {keys_2}.', // @translate
                [
                    'keys' => implode(', ', array_keys($samlAttributesCanonical)),
                    'keys_2' => implode(', ', array_keys($samlAttributesFriendly)),
                ]
            );
            $this->logger()->err($message->getMessage(), $message->getContext());
            // Since this is a config or idp error, redirect to local login.
            return $this->redirect()->toRoute('login');
        }

        $name = $samlAttributesFriendly[array_search('name', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('name', $this->attributesMapCanonical)][0]
            ?? $samlAttributesCanonical[array_search('name', $attributesMap)][0]
            ?? null;

        // The map is already checked.
        $roles = $this->acl->getRoles();
        $rolesMap = $idp['roles_map'];
        $defaultRole = $this->settings('singlesignon_role_default') ?: null;
        $idpRole = $samlAttributesFriendly[array_search('role', $attributesMap)][0]
            ?? $samlAttributesCanonical[array_search('role', $this->attributesMapCanonical)][0]
            ?? null;
        $role = $rolesMap ? $rolesMap[$idpRole] ?? null : $idpRole;
        if (!in_array($role, $roles)) {
            if ($defaultRole && in_array($defaultRole, $roles)) {
                $role = $defaultRole;
            } else {
                $role = in_array('guest', $roles) ? 'guest' : Acl::ROLE_RESEARCHER;
            }
        }

        $user = $this->entityManager
            ->getRepository(\Omeka\Entity\User::class)
            ->findOneBy(['email' => $email]);

        $activeSsoServices = $this->settings()->get('singlesignon_services', ['sso']);

        if (empty($user)) {
            if (!in_array('jit', $activeSsoServices)) {
                $message = new PsrMessage('Automatic registering is disabled.'); // @translate
                $this->messenger()->addError($message);
                return $this->redirect()->toUrl($redirectUrl);
            }

            if (!$name) {
                $message = new PsrMessage(
                    'No name provided or mapped. Available canonical attributes for this IdP: {keys}. Available friendly attributes for this IdP: {keys_2}.', // @translate
                    [
                        'keys' => implode('", "', array_keys($samlAttributesCanonical)),
                        'keys_2' => implode('", "', array_keys($samlAttributesFriendly)),
                    ]
                );
                $this->logger()->warn($message->getMessage(), $message->getContext());
                $name = $email;
            }

            // For security, a new user cannot be an admin.
            if ($this->acl->isAdminRole($role)) {
                if ($defaultRole && in_array($defaultRole, $roles) && !$this->acl->isAdminRole($defaultRole)) {
                    $role = $defaultRole;
                } else {
                    $role = in_array('guest', $roles) ? 'guest' : Acl::ROLE_RESEARCHER;
                }
            }

            $user = new User();
            $user->setEmail($email);
            $user->setName($name);
            $user->setRole($role);
            $user->setIsActive(true);

            $this->entityManager->persist($user);
            $this->entityManager->flush();

            // Useful?
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

            // Other settings.
            /** @var \Omeka\Settings\UserSettings $userSettings */
            $userSettings = $this->userSettings();
            $userSettings->setTargetId($user->getId());
            foreach ($attributesMap as $idpKey => $key) {
                if (in_array($key, ['email', 'name', 'role'])) {
                    continue;
                }
                $value = $samlAttributesFriendly[$idpKey][0]
                    ?? $samlAttributesCanonical[$idpKey][0]
                    ?? null;
                if ($value !== null) {
                    $userSettings->set($key, $value);
                }
            }

            //Group Module Settings to apply default groups
            if (class_exists(\Group\Module::class, false)) {
                $settings = $this->settings();
                $groups = $settings->get('singlesignon_groups_default', []);
                if ($groups) {
                    $groupsToAssign = $this->api()->search(
                        'groups',
                        ['name' => $groups],
                        ['responseContent' => 'resource']
                    )->getContent();

                    foreach ($groupsToAssign as $group) {
                        $groupEntity = new \Group\Entity\GroupUser($group, $user);
                        $this->entityManager->persist($groupEntity);
                    }
                    $this->entityManager->flush();
                }
            }

            // Static settings.
            $staticSettings = $idp['user_settings'];
            foreach ($staticSettings as $key => $value) {
                $userSettings->set($key, $value);
            }
        } elseif (!$user->isActive()) {
            $message = new PsrMessage(
                'User "{email}" is inactive.', // @translate
                ['email' => $email]
            );
            $this->messenger()->addError($message);
            $this->logger()->warn($message->getMessage(), $message->getContext());
            // Since this is a non-authorized user, return to redirect url.
            return $this->redirect()->toUrl($redirectUrl);
        } elseif (in_array('update_user_name', $activeSsoServices)) {
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

        // Store some data for module Access: rights may be related to idps.
        /** @var \Omeka\Settings\UserSettings $userSettings */
        $userSettings = $this->userSettings();
        $userSettings->setTargetId($user->getId());
        $userSettings->set('connection_authenticator', 'SingleSignOn');
        $userSettings->set('connection_idp', $idpEntityId);
        $userSettings->set('connection_last', (new DateTime('now'))->format('Y-m-d H:i:s'));

        $this->messenger()->addSuccess(new PsrMessage('Successfully logged in.')); // @translate

        $eventManager = $this->getEventManager();
        $eventManager->trigger('user.login', $user);

        // Prepare logout service.
        $session = $sessionManager->getStorage();
        $session->offsetSet('saml_name_id', $samlAuth->getNameId());
        $session->offsetSet('saml_name_id_format', $samlAuth->getNameIdFormat());
        $session->offsetSet('saml_name_id_name_qualifier', $samlAuth->getNameIdNameQualifier());
        $session->offsetSet('saml_session_index', $samlAuth->getSessionIndex());

        // Check if there is a RelayState in the response and redirects.
        if ($this->getRequest()->getPost('RelayState')) {
            $redirectUrl = $this->getRequest()->getPost('RelayState');
        } else {
            $redirectUrl = $this->redirectUrl();
        }
        return $this->redirect()->toUrl($redirectUrl);
    }

    /**
     * Log out on the IdP via the SLS (single logout service).
     */
    public function slsAction()
    {
        // The redirect url can be bypassed by IdP when logout is successful.
        $redirectUrl = $this->params()->fromQuery('redirect_url')
            ?: $this->url()->fromRoute('top');

        $idpName = $this->params()->fromRoute('idp')
            ?: $this->idpNameFromRequest();

        $idp = $idpName
            ? $this->idpData($idpName, true)
            : $this->providerData;
        if (!$idp['entity_id']) {
            $this->messenger()->addError(new PsrMessage('No IdP with this name.')); // @translate
            return $this->redirect()->toRoute('login', [], ['query' => ['redirect_url' => $redirectUrl]]);
        }

        $idpEntityId = $idp['entity_id'];

        $configSso = $this->validConfigSso($idpEntityId, true);
        if (empty($configSso['sp']['singleLogoutService'])) {
            $this->messenger()->addSuccess('Successfully logged out'); // @translate
            // Allows to process core log out.
            return $this->redirect()->toUrl('logout');
        }

        $this->authentication->clearIdentity();

        $samlAuth = new SamlAuth($configSso);
        $sloUrl = $samlAuth->processSLO();

        $sessionManager = Container::getDefaultManager();
        $sessionManager->destroy();

        $errors = $samlAuth->getErrors();
        if ($errors) {
            $lastErrorReason = $samlAuth->getLastErrorReason();
            if ($lastErrorReason) {
                $message = new PsrMessage(
                    'Single logout service failed: {errors}. {error_last}', // @translate
                    [
                        'errors' => implode(', ', $errors),
                        'error_last' => $lastErrorReason,
                    ]
                );
            } else {
                $message = new PsrMessage(
                    'Single logout service failed: {errors}', // @translate
                    ['errors' => implode(', ', $errors)]
                );
            }
            $this->messenger()->addError($message);
            $this->logger()->err($message->getMessage(), $message->getContext());
            return $this->redirect()->toUrl($redirectUrl);
        }

        if ($sloUrl) {
            return $this->redirect()->toUrl($sloUrl);
        }

        $this->messenger()->addSuccess(new PsrMessage('Successfully logged out.')); // @translate
        return $this->redirect()->toUrl($redirectUrl);
    }

    /**
     * Get the entity id from the idp short id (idp name).
     */
    protected function idpEntityIdFromIdpName(?string $idpName): ?string
    {
        if (!$idpName) {
            return null;
        }

        $idps = $this->settings()->get('singlesignon_idps', []);
        if (isset($idps[$idpName]['entity_id'])) {
            return $idps[$idpName]['entity_id'];
        }

        // Flat array to map idp id / idp name.
        $idpNames = array_column($idps, 'entity_short_id', 'entity_id');
        $idpEntityId = array_search($idpName, $idpNames);
        if ($idpEntityId) {
            return $idpEntityId;
        }

        // Is it still usefull?
        // Flat array to map idp id / idp host.
        $idpHosts = array_column($idps, 'host', 'entity_id');
        $idpEntityId = array_search($idpName, $idpHosts);
        if ($idpEntityId) {
            return $idpEntityId;
        }

        $idpUrls = array_column($idps, 'metadata_url', 'entity_id');
        $idpEntityId = array_search($idpName, $idpUrls);
        if ($idpEntityId) {
            return $idpEntityId;
        }

        // Probably an invalid idp.
        return isset($idps[$idpName])
            ? $idpName
            : null;
    }

    /**
     * Get idp data as array. If no idp is set, return data with empty values.
     *
     * Idp certificate may be updated when outdated.
     */
    protected function idpData(string $idpEntityId, bool $update = false): array
    {
        $settings = $this->settings();
        $idps = $settings->get('singlesignon_idps', []);

        if (!isset($idps[$idpEntityId])) {
            $idpEntityId = $this->idpEntityIdFromIdpName($idpEntityId);
        }

        $idp = $idps[$idpEntityId] ?? [];

        // Append old and new keys to allow to log in during config migration.
        if ($idp) {
            foreach ($idp as $key => $value) {
                if (mb_substr((string) $key, 0, 4) === 'idp_') {
                    $idp[mb_substr($key, 4)] ??= $value;
                }
            }
        }

        $idp += $this->providerData;

        $updateMode = $settings->get('metadata_update_mode') ?: 'auto';

        // Update idp data when possible, once a day.
        $toUpdate = $update
            && $updateMode !== 'manual'
            && $idpEntityId
            && $idp['entity_id']
            && (!empty($idp['federation_url']) || !empty($idp['metadata_url']))
            && (
                // Init and store if missing.
                empty($idp['date'])
                // Update once a day.
                || (new \DateTimeImmutable($idp['date']))->setTime(0, 0, 0)
                    ->diff((new \DateTimeImmutable('now'))->setTime(0, 0, 0), true)
                    ->format('%a') >= 1
            );

        if ($toUpdate) {
            /**
             * @see \SingleSignOn\Mvc\Controller\Plugin\IdpMetadata
             * @see \SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata
             */
            $idpMeta = !empty($idp['federation_url'])
                ? $this->ssoFederationMetadata($idp['federation_url'], $idp['entity_id'], false)
                : $this->idpMetadata($idp['metadata_url'], false);
            if ($idpMeta) {
                // Keep some data.
                $idpMeta['entity_name'] = $idpMeta['entity_name'] ?: $idp['entity_name'];
                $idpMeta['attributes_map'] = $idp['attributes_map'];
                $idpMeta['roles_map'] = $idp['roles_map'];
                $idpMeta['user_settings'] = $idp['user_settings'];
                $idpMeta['metadata_update_mode'] = $idp['metadata_update_mode'];
                // When defined manually.
                if ($updateMode === 'auto_except_id' && !empty($idp['entity_id'])) {
                    $idpMeta['entity_id'] = $idp['entity_id'];
                }
                $idp = $idpMeta;
                $idps[$idpEntityId] = $idp;
                $settings->set('singlesignon_idps', $idps);
            }
        }

        return $idp;
    }

    /**
     * Get xml metadata from the idp.
     *
     * A message of error may be prepared for messenger
     *
     * @return ?string Checked xml metadata.
     */
    protected function idpMetadataXml(string $idpEntityId): ?string
    {
        $idp = $idpEntityId
            ? $this->idpData($idpEntityId, false)
            : $this->providerData;
        if (!$idp['entity_id']) {
            $this->messenger()->addError(new PsrMessage('No IdP with this name.')); // @translate
            return null;
        }

        $idpEntityId = $idp['entity_id'];

        $idpFullName = $idp['entity_short_id'] && $idp['entity_short_id'] !== $idpEntityId
            ? sprintf('%s (%s)', $idp['entity_short_id'], $idpEntityId)
            : $idpEntityId;

        if (empty($idp['federation_url']) && empty($idp['metadata_url'])) {
            $this->messenger()->addError(new PsrMessage(
                'The IdP "{idp}" has no available metadata.', // @translate
                ['idp' => $idpFullName]
            ));
            return null;
        }

        if (empty($idp['metadata_url'])) {
            // <md:EntityDescriptor entityID="http://adfs.devinci.fr/adfs/services/trust">
            $federationUrl = $idp['federation_url'];
            $federationString = $this->downloadUrl($federationUrl);
            if (!$federationString) {
                $this->messenger()->addError(new PsrMessage(
                    'The IdP "{idp}" has no available metadata.', // @translate
                    ['idp' => $idpFullName]
                ));
                return null;
            }

            /** @var \SimpleXMLElement $xml */
            $xml = @simplexml_load_string($federationString);
            if (!$xml) {
                $this->messenger()->addError(new PsrMessage(
                    'The federation url {url} does not return valid xml metadata.', // @translate
                    ['url' => $federationUrl]
                ));
                return null;
            }

            // Extract the xml for the entity.
            $namespaces = $xml->getDocNamespaces();
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

            $idpEntityId = $idp['entity_id'];
            if ($namespaces) {
                $baseXpath = sprintf('/md:EntitiesDescriptor/md:EntityDescriptor[@entityID="%s"]', $idpEntityId);
                $idpXml = $registerXpathNamespaces($xml)->xpath($baseXpath);
            } else {
                $baseXpath = sprintf('/EntitiesDescriptor/EntityDescriptor[@entityID="%s"]', $idpEntityId);
                $idpXml = $xml->xpath($baseXpath);
            }
            if (!$idpXml) {
                return null;
            }
            $idpString = $idpXml[0]->asXml();
            return '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL
                . $idpString;
        }

        $idpString = $this->downloadUrl($idp['metadata_url']);
        if (!$idpString) {
            $this->messenger()->addError(new PsrMessage(
                'The IdP "{idp}" has no available metadata.', // @translate
                ['idp' => $idpFullName]
            ));
            return null;
        }

        /** @var \SimpleXMLElement $idpXml */
        $idpXml = @simplexml_load_string($idpString);
        if (!$idpXml) {
            $this->messenger()->addError(new PsrMessage(
                'The IdP "{idp}" has no valid xml metadata.', // @translate
                ['idp' => $idpFullName]
            ));
            return null;
        }

        return $idpString;
    }

    /**
     * Get the idp name from request, in particular for acs and sls.
     *
     * @todo Find a way to set the idp name via the routing for the second request.
     */
    protected function idpNameFromRequest(): ?string
    {
        $origin = $this->getRequest()->getHeaders()->get('Origin');
        $domain = $origin ? $origin->getFieldValue() : null;
        return $domain ? parse_url($domain, PHP_URL_HOST) : null;
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

        return $this->redirectToAdminOrSite()
            ?: $this->url()->fromRoute('top');
    }

    /**
     * Redirect to admin or site according to the role of the user and setting.
     *
     * @return \Laminas\Http\Response
     *
     * Adapted:
     * @see \Guest\Controller\Site\AbstractGuestController::redirectToAdminOrSite()
     * @see \Guest\Site\BlockLayout\TraitGuest::redirectToAdminOrSite()
     * @see \SingleSignOn\Controller\SsoController::redirectToAdminOrSite()
     */
    protected function redirectToAdminOrSite(): ?string
    {
        $redirect = $this->settings()->get('singlesignon_redirect');
        switch ($redirect) {
            case empty($redirect):
            case 'home':
                if ($this->userIsAllowed('Omeka\Controller\Admin\Index', 'index')) {
                    return $this->url()->fromRoute('admin');
                }
                // no break.
            case 'site':
            case 'me' && class_exists(\Guest\Module::class, false):
                $siteSlug = $this->params()->fromRoute('site-slug') ?: $this->viewHelpers()->get('defaultSite')('slug');
                return $siteSlug
                    ? $this->url()->fromRoute($redirect === 'me' ? 'site/guest' : 'site', ['site-slug' => $siteSlug])
                    : $this->url()->fromRoute('top');
            case 'top':
                return $this->url()->fromRoute('top');
            default:
                return $redirect;
        }
    }

    protected function downloadUrl(string $url): ?string
    {
        $this->httpClient->setUri($url);
        $response = $this->httpClient->send();
        if ($response->isSuccess()) {
            try {
                return $response->getBody();
            } catch (\Laminas\Http\Exception\RuntimeException $e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Validate the SSO config of the current sp or any managed idp.
     */
    protected function validConfigSso(?string $idpEntityId, bool $throw = false): ?array
    {
        try {
            $configSso = $this->configSso($idpEntityId);
            new SamlSettings($configSso, empty($idpEntityId));
        } catch (SamlError $e) {
            $message = new PsrMessage(
                'SSO service has an error in configuration: {exception}', // @translate
                ['exception' => $e]
            );
            $this->logger()->err($message->getMessage(), $message->getContext());
            if (!$throw) {
                return null;
            }
            $message = new PsrMessage(
                'SSO service is not available. Ask admin to config it.' // @translate
            );
            throw new RuntimeException((string) $message);
        } catch (\Exception $e) {
            $this->logger()->err('SSO service is unavailable.'); // @translate
            if (!$throw) {
                return null;
            }
            $message = new PsrMessage(
                'SSO service is unavailable. Ask admin to config it.' // @translate
            );
            throw new \Omeka\Mvc\Exception\RuntimeException((string) $message);
        }

        $activeSsoServices = $this->settings()->get('singlesignon_services', ['sso']);

        if (!in_array('sso', $activeSsoServices)
            || empty($configSso['sp']['assertionConsumerService']['url'])
        ) {
            unset($configSso['sp']['assertionConsumerService']);
        }

        if (!in_array('sls', $activeSsoServices)
            || empty($configSso['sp']['singleLogoutService']['url'])
        ) {
            unset($configSso['sp']['singleLogoutService']);
        }

        return $configSso;
    }

    /**
     * Get the SSO config of the current sp and a managed idp, if any.
     *
     * @param string|null $idpEntityId Null means the sp entity id.
     */
    protected function configSso(?string $idpEntityId): array
    {
        $url = $this->url();
        $settings = $this->settings();

        $certsBasePath = $settings->get('singlesignon_sp_sign_x509_path');
        if ($certsBasePath) {
            defined('ONELOGIN_CUSTOMPATH') || define('ONELOGIN_CUSTOMPATH', rtrim($certsBasePath, '/') . '/');
        }

        $spHostName = $settings->get('singlesignon_sp_host_name');
        if ($spHostName) {
            $baseUrlSso = $spHostName . rtrim($url->fromRoute('sso', [], ['force_canonical' => false]), '/');
        } else {
            $baseUrlSso = rtrim($url->fromRoute('sso', [], ['force_canonical' => true]), '/');
        }

        $spEntityId = $settings->get('singlesignon_sp_entity_id') ?: $baseUrlSso;

        $spSignX509cert = trim($settings->get('singlesignon_sp_sign_x509_certificate') ?: '');
        $spSignPrivateKey = trim($settings->get('singlesignon_sp_sign_x509_private_key') ?: '');
        if ($spSignX509cert && $spSignPrivateKey) {
            // Remove windows and apple issues (managed later anyway).
            $spSignX509cert = str_replace(["\r\n", "\n\r", "\r"], "\n", $spSignX509cert);
            $spSignPrivateKey = str_replace(["\r\n", "\n\r", "\r"], "\n", $spSignPrivateKey);
        } else {
            if ($spSignX509cert || $spSignPrivateKey) {
                $this->logger()->err('The cerificate for the signature is incomplete.'); // @translate
            }
            $spSignX509cert = null;
            $spSignPrivateKey = null;
        }

        // Openssl remove header, footer and end of lines automatically.
        $spCryptX509cert = trim($settings->get('singlesignon_sp_crypt_x509_certificate') ?: '');
        $spCryptPrivateKey = trim($settings->get('singlesignon_sp_crypt_x509_private_key') ?: '');
        if ($spCryptX509cert && $spCryptPrivateKey) {
            // Remove windows and apple issues (managed later anyway).
            $spCryptX509cert = str_replace(["\r\n", "\n\r", "\r"], "\n", $spCryptX509cert);
            $spCryptPrivateKey = str_replace(["\r\n", "\n\r", "\r"], "\n", $spCryptPrivateKey);
        } else {
            if ($spCryptX509cert && $spCryptPrivateKey) {
                $this->logger()->err('The cerificate for the encryption is incomplete.'); // @translate
            }
            $spCryptX509cert = null;
            $spCryptPrivateKey = null;
        }

        // When there is no idp name, get the config of the sp.
        $idp = $idpEntityId
            ? $this->idpData($idpEntityId, true)
            : $this->providerData;

        /**
         * @see vendor/onelogin/php-saml/settings_example.php
         * @see vendor/onelogin/php-saml/advanced_settings_example.php
         */
        $providerSettings = [
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
                'entityId' => $spEntityId,

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
                // 'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                'NameIDFormat' => $settings->get('singlesignon_sp_name_id_format', \OneLogin\Saml2\Constants::NAMEID_UNSPECIFIED),

                // Usually x509cert and privateKey of the SP are provided by files placed at
                // the certs folder. But we can also provide them with the following parameters
                'x509cert' => $spSignX509cert,
                'privateKey' => $spSignPrivateKey,

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
                'entityId' => $idp['entity_id'],

                // SSO endpoint info of the IdP. (Authentication Request protocol)
                'singleSignOnService' => [
                    // URL Target of the IdP where the SP will send the Authentication Request Message
                    'url' => $idp['sso_url'],
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],

                // SLO endpoint info of the IdP.
                'singleLogoutService' => [
                    // URL Location of the IdP where the SP will send the SLO Request
                    'url' => $idp['slo_url'],
                    // URL location of the IdP where the SP SLO Response will be sent (ResponseLocation)
                    // if not set, url for the SLO Request will be used
                    'responseUrl' => '',
                    // SAML protocol binding to be used when returning the <Response>
                    // message.  Onelogin Toolkit supports for this endpoint the
                    // HTTP-Redirect binding only
                    'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                ],

                // Public x509 certificate of the IdP
                'x509cert' => empty($idp['sign_x509_certificates']) ? null : reset($idp['sign_x509_certificates']),

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

            // Compression settings
            // Handle if the getRequest/getResponse methods will return the Request/Response deflated.
            // But if we provide a $deflate boolean parameter to the getRequest or getResponse
            // method it will have priority over the compression settings.
            'compress' => [
                'requests' => true,
                'responses' => true,
            ],

            // Security settings
            'security' => [

                // Signatures and encryptions offered.

                // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
                // will be encrypted.
                'nameIdEncrypted' => false,

                // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
                // will be signed.              [The Metadata of the SP will offer this info]
                'authnRequestsSigned' => !empty($spSignX509cert),

                // Indicates whether the <samlp:logoutRequest> messages sent by this SP
                // will be signed.
                'logoutRequestSigned' => !empty($spSignX509cert),

                // Indicates whether the <samlp:logoutResponse> messages sent by this SP
                // will be signed.
                'logoutResponseSigned' => !empty($spSignX509cert),

                /* Sign the Metadata
                 False || True (use sp certs) || array (
                        keyFileName => 'metadata.key',
                        certFileName => 'metadata.crt'
                    )
                    || array (
                        'x509cert' => '',
                        'privateKey' => ''
                    )
                 */
                'signMetadata' => false,

                // signatures and encryptions required.

                // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
                // <samlp:LogoutResponse> elements received by this SP to be signed.
                'wantMessagesSigned' => false,

                // Indicates a requirement for the <saml:Assertion> elements received by
                // this SP to be encrypted.
                'wantAssertionsEncrypted' => false,

                // Indicates a requirement for the <saml:Assertion> elements received by
                // this SP to be signed.        [The Metadata of the SP will offer this info]
                'wantAssertionsSigned' => !empty($spSignX509cert),

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

                // If true, Destination URL should strictly match to the address to
                // which the response has been sent.
                // Notice that if 'relaxDestinationValidation' is true an empty Destintation
                // will be accepted.
                'destinationStrictlyMatches' => false,

                // If true, the toolkit will not raised an error when the Statement Element
                // contain atribute elements with name duplicated
                'allowRepeatAttributeName' => false,

                // If true, SAMLResponses with an InResponseTo value will be rejectd if not
                // AuthNRequest ID provided to the validation method.
                'rejectUnsolicitedResponsesWithInResponseTo' => false,

                // Algorithm that the toolkit will use on signing process. Options:
                //    'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
                //    'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
                //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
                //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
                // Notice that rsa-sha1 is a deprecated algorithm and should not be used
                'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

                // Algorithm that the toolkit will use on digest process. Options:
                //    'http://www.w3.org/2000/09/xmldsig#sha1'
                //    'http://www.w3.org/2001/04/xmlenc#sha256'
                //    'http://www.w3.org/2001/04/xmldsig-more#sha384'
                //    'http://www.w3.org/2001/04/xmlenc#sha512'
                // Notice that sha1 is a deprecated algorithm and should not be used
                'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',

                // Algorithm that the toolkit will use for encryption process. Options:
                // 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
                // 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
                // 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
                // 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
                // 'http://www.w3.org/2009/xmlenc11#aes128-gcm'
                // 'http://www.w3.org/2009/xmlenc11#aes192-gcm'
                // 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
                // Notice that aes-cbc are not consider secure anymore so should not be used
                'encryption_algorithm' => 'http://www.w3.org/2009/xmlenc11#aes128-gcm',

                // ADFS URL-Encodes SAML data as lowercase, and the toolkit by default uses
                // uppercase. Turn it True for ADFS compatibility on signature verification
                'lowercaseUrlencoding' => false,
            ],

            /*
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
            */

            /*
            // Organization information template, the info in en_US lang is recomended, add more if required
            'organization' => [
                'en-US' => [
                    'name' => '',
                    'displayname' => '',
                    'url' => ''
                ],
            ],
            */

            /*
            // Interoperable SAML 2.0 Web Browser SSO Profile [saml2int]   http://saml2int.org/profile/current
            'authnRequestsSigned' => false,    // SP SHOULD NOT sign the <samlp:AuthnRequest>,
            // MUST NOT assume that the IdP validates the sign
            'wantAssertionsSigned' => true,
            'wantAssertionsEncrypted' => true, // MUST be enabled if SSL/HTTPs is disabled
            'wantNameIdEncrypted' => false,
            */

        ];

        if ($spCryptX509cert && $spSignPrivateKey) {
            $providerSettings['sp']['x509certNew'] = $spCryptX509cert;
        }

        if (count($idp['sign_x509_certificates'] ?? []) > 1
            || !empty($idp['crypt_x509_certificates'])
        ) {
            $providerSettings['idp']['x509certMulti'] = [
                'signing' => $idp['sign_x509_certificates'] ?? [],
                'encryption' => $idp['crypt_x509_certificates'] ?? [],
            ];
        }

        return $providerSettings;
    }
}
