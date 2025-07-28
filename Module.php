<?php declare(strict_types=1);

namespace SingleSignOn;

if (!class_exists('Common\TraitModule', false)) {
    require_once dirname(__DIR__) . '/Common/TraitModule.php';
}

use Common\Stdlib\PsrMessage;
use Common\TraitModule;
use Laminas\EventManager\Event;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\ModuleManager\ModuleManager;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\Mvc\MvcEvent;
use Laminas\View\Renderer\PhpRenderer;
use Omeka\Api\Representation\UserRepresentation;
use Omeka\Module\AbstractModule;
use OneLogin\Saml2\Utils;

/**
 * Single Sign-On.
 *
 * @copyright Daniel Berthereau, 2023-2025
 * @license http://www.cecill.info/licences/Licence_CeCILL_V2.1-en.txt
 */
class Module extends AbstractModule
{
    use TraitModule;

    const NAMESPACE = __NAMESPACE__;

    public function init(ModuleManager $moduleManager): void
    {
        require_once __DIR__ . '/vendor/autoload.php';
    }

    public function onBootstrap(MvcEvent $event): void
    {
        parent::onBootstrap($event);

        /** @var \Omeka\Permissions\Acl $acl */
        $acl = $this->getServiceLocator()->get('Omeka\Acl');
        $acl
            // Anybody can log in.
            ->allow(
                null,
                [\SingleSignOn\Controller\SsoController::class],
            );
    }

    protected function preInstall(): void
    {
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $translate = $plugins->get('translate');

        if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.71')) {
            $message = new \Omeka\Stdlib\Message(
                $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
                'Common', '3.4.71'
            );
            throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
        }
    }

    public function attachListeners(SharedEventManagerInterface $sharedEventManager): void
    {
        $sharedEventManager->attach(
            // Many controller can call this trigger, so use the joker.
            '*',
            'view.login.after',
            [$this, 'handleViewLogin']
        );

        // Add the guest main infos to the user show admin pages.
        $sharedEventManager->attach(
            'Omeka\Controller\Admin\User',
            'view.details',
            [$this, 'viewUserDetails']
        );
        $sharedEventManager->attach(
            'Omeka\Controller\Admin\User',
            'view.show.after',
            [$this, 'viewUserShowAfter']
        );
    }

    public function getConfigForm(PhpRenderer $view)
    {
        $services = $this->getServiceLocator();

        $settings = $services->get('Omeka\Settings');
        $defaultSettings = $this->getModuleConfig('config');

        $data = [];
        foreach ($defaultSettings as $name => $value) {
            $val = $settings->get($name, is_array($value) ? [] : null);
            $data[$name] = $val;
        }

        // Remove the federated idps from the list of idps to keep only the
        // manually defined ones.
        $data['singlesignon_idps'] = array_filter($data['singlesignon_idps'] ?: [], fn ($v) => empty($v['federation_url']) || !empty($v['metadata_use_federation_data']));
        // Append the first certificate for manual idp.
        $data['singlesignon_idps'] = array_map(function ($v) {
            $v['sign_x509_certificate'] = empty($v['sign_x509_certificates']) ? null : reset($v['sign_x509_certificates']);
            $v['crypt_x509_certificate'] = empty($v['crypt_x509_certificates']) ? null : reset($v['crypt_x509_certificates']);
            return $v;
        }, $data['singlesignon_idps']);

        // Data with empty key is always invalid and breaks form.
        // Normally not present if the config form is well handled.
        unset($data['singlesignon_idps']['']);

        /** @var \SingleSignOn\Form\ConfigForm $form */
        $form = $services->get('FormElementManager')->get(\SingleSignOn\Form\ConfigForm::class);
        $form->init();
        $form->setData($data);

        $plugins = $view->getHelperPluginManager();
        $assetUrl = $plugins->get('assetUrl');
        $formRow = $plugins->get('formRow');

        $view->headScript()
            ->appendFile($assetUrl('js/single-sign-on-admin.js', 'SingleSignOn'), 'text/javascript', ['defer' => 'defer']);

        $form->prepare();

        // The rendering of Collection is not automatic, but required to set the
        // good name of elements of the fieldset.
        /** @see https://docs.laminas.dev/laminas-form/v3/collections/ */
        // return $renderer->formCollection($form, true);

        // The form is already open in page actions, but without id or name.
        // $html .= $view->form()->openTag($form);
        $html = '';
        foreach ($form->getElements() as $element) {
            $html .= $formRow($element);
        }

        // Append a message inside the main fieldset.
        /** @var \Laminas\Form\Element\Collection $collection */
        $collection = $form->get('singlesignon_idps')
            ->setLabelOption('disable_html_escape', true);
        $collectionNote = '<p>'
            . $view->translate('When the metadata url of an IdP is set, its form will be automatically filled and updated each day.') // @translate
            . '</p>';
        $collectionNote .= '<p>'
            . $view->translate('Warning: some IdPs hide the name, so you may fill it yourself.') // @translate
            . ' '
            . $view->translate('Furthermore, IdP keys still need to be mapped, at least for name.') // @translate
            . '</p>';

        // IdP are rendered as collection.
        $html .= $view->formCollection()
            ->setLabelWrapper('<legend>%s</legend>' . $collectionNote)
            ->render($collection);

        // The form is closed in parent, so don't close it here, else the csrf
        // will be outside.
        // $html .= $view->form()->closeTag();
        return $html;
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $result = $this->handleConfigFormAuto($controller);
        if (!$result) {
            return false;
        }

        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         * @var \Omeka\Permissions\Acl $acl
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         * @var \SingleSignOn\Mvc\Controller\Plugin\IdpMetadata $idpMetadata
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $acl = $services->get('Omeka\Acl');
        $messenger = $plugins->get('messenger');
        $idpMetadata = $plugins->get('idpMetadata');

        $this->validateDefaultRole();

        // Normally, these values are not stored.
        $settings->delete('singlesignon_sp_sign_create_certificate');
        $settings->delete('singlesignon_sp_crypt_create_certificate');

        $createCertificateSign = !empty($_POST['singlesignon_sp_sign_create_certificate']);
        $createCertificateCrypt = !empty($_POST['singlesignon_sp_crypt_create_certificate']);

        // Messages are displayed, but data are stored in all cases.

        $this->checkConfigSP($createCertificateSign, $createCertificateCrypt);

        // Check federation before filling it.
        $this->checkConfigFederation();

        $federation = $settings->get('singlesignon_federation');
        $federationIdps = $federation
            ? $this->prepareFederation($federation)
            : [];

        // Check and finalize idps.
        $hasError = false;
        $specificIdps = $settings->get('singlesignon_idps') ?: [];
        $cleanIdps = $this->prepareIdps($specificIdps, $federationIdps, $hasError);
        if ($hasError) {
            return false;
        }

        // Store the federated idps and the locally defined idps in a single
        // place to simplify interface and management.
        // The local idps may override the federated ones.
        // Keep them first.

        $mergedIdps = $cleanIdps + $federationIdps;
        $settings->set('singlesignon_idps', $mergedIdps);

        return true;
    }

    /**
     * For security, forbid admin roles for new user.
     */
    protected function validateDefaultRole(): void
    {
        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         * @var \Omeka\Permissions\Acl $acl
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $acl = $services->get('Omeka\Acl');
        $messenger = $plugins->get('messenger');

        $defaultRole = $settings->get('singlesignon_role_default');
        if ($defaultRole && $acl->isAdminRole($defaultRole)) {
            $roles = $acl->getRoles();
            $role = in_array('guest', $roles) ? 'guest' : \Omeka\Permissions\Acl::ROLE_RESEARCHER;
            $settings->set('singlesignon_role_default', $role);
            $message = new PsrMessage(
                'For security, the default role cannot be an admin one. The default role was set to {role}.', // @translate
                ['role' => $role]
            );
            $messenger->addWarning($message);
        }
    }

    /**
     * Display the SSO login links on the login page.
     */
    public function handleViewLogin(Event $event): void
    {
        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        $loginView = $settings->get('singlesignon_append_links_to_login_view');
        if (!$loginView) {
            return;
        }

        $selectors = ['link', 'button', 'select'];
        if ($settings->get('singlesignon_federation')) {
            $selector = in_array($loginView, $selectors) ? $loginView : 'select';
        } else {
            $selector = in_array($loginView, $selectors) ? $loginView : 'link';
        }

        /** @var \Laminas\View\Renderer\PhpRenderer $view */
        $view = $event->getTarget();
        echo $view->ssoLoginLinks(['selector' => $selector]);
    }

    public function viewUserDetails(Event $event): void
    {
        $view = $event->getTarget();
        $user = $view->resource;
        $this->viewUserData($view, $user, 'common/user-settings-sso');
    }

    public function viewUserShowAfter(Event $event): void
    {
        $view = $event->getTarget();
        $user = $view->vars()->user;
        $this->viewUserData($view, $user, 'common/user-settings-list-sso');
    }

    protected function viewUserData(PhpRenderer $view, UserRepresentation $user, $template): void
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');
        $userSettings = $services->get('Omeka\Settings\User');
        $userSettings->setTargetId($user->id());

        // Get all idps with user settings, then get all these settings.
        // Get the idp of the user.
        $connectionIdp  = $userSettings->get('connection_idp');
        if (!$connectionIdp) {
            return;
        }

        $idps = $settings->get('singlesignon_idps') ?: [];
        if (!isset($idps[$connectionIdp]) || empty($idps[$connectionIdp]['attributes_map'])) {
            return;
        }

        $attributesMap = empty($idps[$connectionIdp]['attributes_map_hide'])
            ? $idps[$connectionIdp]['attributes_map']
            : array_diff_key($idps[$connectionIdp]['attributes_map'], array_flip($idps[$connectionIdp]['attributes_map_hide']));
        if (!$attributesMap) {
            return;
        }

        echo $view->partial($template,[
            'user' => $user,
            'userSettings' => $userSettings,
            'idpAttributesToSettingsKeys' => $attributesMap,
        ]);
    }

    protected function prepareFederation(string $federation): array
    {
        /**
         * @var \SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata $ssoFederationMetadata
         */
        $services = $this->getServiceLocator();
        $config = $services->get('Config');

        $federations = $config['singlesignon']['federations'];
        if (!isset($federations[$federation])) {
            return [];
        }

        $federationUrl = $federations[$federation];

        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $ssoFederationMetadata = $plugins->get('ssoFederationMetadata');

        $result = $ssoFederationMetadata($federationUrl, null, true);
        if ($result === null) {
            return [];
        }

        uasort($result, fn ($idpA, $idpB) => strcasecmp($idpA['entity_name'], $idpB['entity_name']));

        return $result;
    }

    /**
     * Prepare specific idps.
     *
     * @param array $idps Specific idps.
     * @param array $federationIdps Federated idps.
     * @param bool $hasError Passed by reference to simplify config form handle.
     * @return array Cleaned specific idps.
     */
    protected function prepareIdps(array $idps, array $federationIdps, bool &$hasError): array
    {
        $result = [];
        // Here, the keys of idps are provided by the form and may be invalid.
        $key = -1;
        foreach ($idps as $idp) {
            ++$key;
            unset($idp['minus'], $idp['up'], $idp['down'], $idp['is_invalid']);
            if ($idp) {
                $idp = $this->checkConfigIdp($idp, $federationIdps);
                $hasError = $hasError || !empty($idp['is_invalid']);
                // Keep invalid idp for user fixing in the config form.
                $entityId = empty($idp['entity_id']) ? "no-entity-id-$key" : $idp['entity_id'];
                $result[$entityId] = $idp;
            }
        }
        return $result;
    }

    protected function checkConfigFederation(): bool
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        $federation = $settings->get('singlesignon_federation');
        $idps = $settings->get('singlesignon_idps');
        if (!empty($federation) && !empty($idps)) {
            /**@var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
            $plugins = $services->get('ControllerPluginManager');
            $messenger = $plugins->get('messenger');
            $messenger->addNotice(new PsrMessage(
                'A federation is specified and a list of idps too. The idps defined manually overwrite the federation ones with the same name.' // @ŧranslate
            ));
            return false;
        }

        return true;
    }

    /**
     * Check config of an idp. The key "is_invalid" is added for invalid config.
     */
    protected function checkConfigIdp(array $idp, array $federationIdps): array
    {
        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         * @var \Omeka\Permissions\Acl $acl
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         * @var \SingleSignOn\Mvc\Controller\Plugin\IdpMetadata $idpMetadata
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $acl = $services->get('Omeka\Acl');
        $messenger = $plugins->get('messenger');
        $idpMetadata = $plugins->get('idpMetadata');

        $ssoServices = $settings->get('singlesignon_services') ?: [];

        $updateAuto = ($idp['metadata_update_mode'] ?? null) !== 'manual';
        $useFederationData = !empty($idp['metadata_use_federation_data']);
        $keepEntityId = !empty($idp['metadata_keep_entity_id']);
        $entityId = trim($idp['entity_id'] ?? '');
        $entityUrl = trim($idp['metadata_url'] ?? '');

        // Store quick cleaning early in any case.
        $idp['metadata_update_mode'] = $updateAuto ? 'auto' : 'manual';
        $idp['metadata_use_federation_data'] = $useFederationData;
        $idp['metadata_keep_entity_id'] = $keepEntityId;
        $idp['metadata_url'] = $entityUrl;
        $idp['entity_id'] = $entityId;
        $idp['entity_name'] ??= null;
        $idp['entity_short_id'] ??= null;

        // Only the first cerfificate for signing and crypting is stored.
        // So fill all of them when a url is set or not.
        // The idp store multiple certificates, but the form has only one.
        $idp['sign_x509_certificates'] = $this->checkX509Certificates(
            empty($idp['sign_x509_certificate']) ? [] : [$idp['sign_x509_certificate']],
            $idp['metadata_url'] ?: $idp['entity_id'] ?: $idp['entity_name'] ?: $idp['entity_short_id']
        );
        $idp['crypt_x509_certificates'] = $this->checkX509Certificates(
            empty($idp['crypt_x509_certificate']) ? [] : [$idp['crypt_x509_certificate']],
            $idp['metadata_url'] ?: $idp['entity_id'] ?: $idp['entity_name'] ?: $idp['entity_short_id']
        );
        unset($idp['sign_x509_certificate']);
        unset($idp['crypt_x509_certificate']);

        if (!$entityId && !$entityUrl) {
            $idp['is_invalid'] = true;
            $message = new PsrMessage(
                'An IdP does not have url and no id and is not valid.', // @translate
            );
            $messenger->addError($message);
            return $idp;
        }

        // Check if the idp is filled.
        $isFilled = !empty($idp['entity_name'])
            && !empty($idp['sign_x509_certificates'])
            && (!in_array('sso', $ssoServices) || !empty($idp['sso_url']))
            && (!in_array('sls', $ssoServices) || !empty($idp['slo_url']));

        if ($isFilled && !$updateAuto) {
            $idp = $this->completeIdpData($idp) + $idp;
            // When an idp is not available, the key should not be empty,
            // so use another key to keep track of it and to avoid an issue
            // somewhere else, for example in form idp fieldset.
            $message = new PsrMessage(
                'The idp "{url}" was manually filled and is not checked neither updated.', // @translate
                ['url' => $idp['metadata_url']]
            );
            $messenger->addWarning($message);
            return $idp;
        }

        $idpMetaFederation = [];
        if ($useFederationData) {
            if (isset($federationIdps[$entityId])) {
                // Unlike simple idp from federation, keep the metadata url.
                $idpMetaFederation = $federationIdps[$entityId];
                $newIdp = array_replace($idp, $idpMetaFederation);
                $newIdp['metadata_url'] = $entityUrl;
                if ($keepEntityId && $entityId) {
                    $newIdp['entity_id'] = $entityId;
                }
                // No more check: this is the federated metadata.
                return $newIdp;
            }
            $messenger->addWarning(new PsrMessage(
                'The option to use metadata from federation for IdP "{url}" is set, but there is no such data.', // @translate
                ['url' => $entityUrl]
            ));
        }

        if ($entityUrl) {
            $idpMeta = $idpMetadata($entityUrl, true);
            if ($idpMeta) {
                $originalIdp = $idp;
                $idp = array_replace($idp, $idpMeta);
                // Avoid issues: keep some data in any cases if something change
                // somewhere else.
                $idp['metadata_update_mode'] = $updateAuto ? 'auto' : 'manual';
                $idp['metadata_use_federation_data'] = $useFederationData;
                $idp['metadata_keep_entity_id'] = $keepEntityId;
                $idp['entity_name'] = $idpMeta['entity_name'] ?: $originalIdp['entity_name'];
                $idp['attributes_map'] = $originalIdp['attributes_map'];
                $idp['roles_map'] = $originalIdp['roles_map'];
                $idp['user_settings'] = $originalIdp['user_settings'];
                if ($keepEntityId) {
                    $idp['entity_id'] = $entityId;
                }
                return $idp;
            }
            $idp['is_invalid'] = true;
            $messenger->addWarning(new PsrMessage(
                'The metadata for IdP "{url}" could not be retrieved.', // @translate
                ['url' => $entityUrl]
            ));
            // Keep going with the passed config.
        }

        $idp['metadata_url'] = null;
        $idp = $this->completeIdpData($idp) + $idp;

        if (empty($idp['entity_id'])) {
            $idp['is_invalid'] = true;
            $message = new PsrMessage(
                'The idp "{url}" seems to be invalid and has no id.', // @translate
                ['url' => $entityUrl]
            );
            $messenger->addWarning($message);
        }

        return $idp;
    }

    protected function completeIdpData(array $idp): array
    {
        $entityId = trim($idp['entity_id'] ?? '');
        $entityName = trim($idp['entity_name'] ?? '');
        $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
        $entityShortId = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;
        $ssoUrl = trim($idp['idp_sso_url'] ?? '');
        $idpHost = $ssoUrl ? parse_url($ssoUrl, PHP_URL_HOST) : null;
        return [
            'entity_id' => $entityId,
            'entity_name' => $entityName ?: $entityShortId,
            'entity_short_id' => $entityShortId,
            'host' => $idpHost,
            'date' => (new \DateTime('now'))->format(\DateTime::ISO8601),
        ];
    }

    protected function checkConfigSP(
        ?bool $createCertificateSign = false,
        ?bool $createCertificateCrypt = false
    ): bool {
        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         */
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        $signCertsBasePath = $settings->get('singlesignon_sp_sign_x509_path');
        $signX509cert = trim($settings->get('singlesignon_sp_sign_x509_certificate') ?: '');
        $signPrivateKey = trim($settings->get('singlesignon_sp_sign_x509_private_key') ?: '');
        $signResult = $this->checkOrCreateCerfificate($signCertsBasePath, $signX509cert, $signPrivateKey, (bool) $createCertificateSign, 'sign');

        $cryptCertsBasePath = $settings->get('singlesignon_sp_crypt_x509_path');
        $cryptX509cert = trim($settings->get('singlesignon_sp_crypt_x509_certificate') ?: '');
        $cryptPrivateKey = trim($settings->get('singlesignon_sp_crypt_x509_private_key') ?: '');
        $cryptResult = $this->checkOrCreateCerfificate($cryptCertsBasePath, $cryptX509cert, $cryptPrivateKey, (bool) $createCertificateCrypt, 'crypt');

        return $signResult && $cryptResult;
    }

    protected function checkOrCreateCerfificate(
        ?string $certsBasePath,
        ?string $x509cert,
        ?string $privateKey,
        bool $createCertificate,
        string $certificateUse
    ): bool {
        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $messenger = $plugins->get('messenger');

        if (!$x509cert && !$privateKey) {
            if ($certsBasePath) {
                $x509certFilePath = $certsBasePath . '/certs/sp.crt';
                $x509cert = file_exists($x509certFilePath) || !is_readable($x509certFilePath) || !filesize($x509certFilePath)
                    ? file_get_contents($x509certFilePath)
                    : '';
                $privateKeyPath = $certsBasePath . '/certs/sp.key';
                $privateKey = file_exists($privateKeyPath) || !is_readable($privateKeyPath) || !filesize($privateKeyPath)
                    ? file_get_contents($privateKeyPath)
                    : '';
                if (!$x509cert || !$privateKey) {
                    $message = new PsrMessage(
                        'A path is set for the certificate ({use}), but it does not contain a directory "certs" with files "sp.crt" and "sp.key".', // @translate
                        ['use' => $certificateUse]
                    );
                    $messenger->addError($message);
                }
            } elseif (!$createCertificate) {
                return true;
            }
        } elseif ($x509cert && !$privateKey) {
            $message = new PsrMessage(
                'The SP public certificate is set, but not the private key ({use}).', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
        } elseif (!$x509cert && $privateKey) {
            $message = new PsrMessage(
                'The SP private key is set, but not the public certificate ({use}).', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
        }

        if ($certsBasePath && ($x509cert || $privateKey)) {
            $message = new PsrMessage(
                'You cannot set a path to the certificate ({use}) and provide them in fields at the same time.', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
            return false;
        }

        if ($createCertificate) {
            if ($certsBasePath || $x509cert || $privateKey) {
                $message = new PsrMessage(
                    'The certicate ({use}) cannot be created when fields "certificate path", "x509 certificate", or "x509 private key" are filled.', // @translate
                    ['use' => $certificateUse]
                );
                $messenger->addError($message);
                return false;
            }
            $certificateData = $settings->get('singlesignon_sp_{$certificateUse}_x509_certificate_data') ?: [];
            [$x509cert, $privateKey] = $this->createCertificate($certificateData);
            if ($x509cert && $privateKey) {
                $message = new PsrMessage(
                    'The x509 certificate ({use}) was created successfully.', // @translate
                    ['use' => $certificateUse]
                );
                $messenger->addSuccess($message);
            } else {
                $message = openssl_error_string();
                $message = new PsrMessage(
                    'An error occurred during creation of the x509 certificate ({use}): {msg}', // @translate
                    ['use' => $certificateUse, 'message' => $message ?: 'Unknown error']
                );
                $messenger->addError($message);
                return false;
            }
        }

        // Remove windows and apple issues.
        $x509cert = strtr($x509cert, ["\r\n" => "\n", "\n\r" => "\n", "\r" => "\n"]);
        $privateKey = strtr($privateKey, ["\r\n" => "\n", "\n\r" => "\n", "\r" => "\n"]);

        // Clean keys.
        $x509cert = Utils::formatCert($x509cert, true);
        $privateKey = Utils::formatPrivateKey($privateKey, true);
        $settings->set("singlesignon_sp_{$certificateUse}_x509_certificate", $x509cert);
        $settings->set("singlesignon_sp_{$certificateUse}_x509_private_key", $privateKey);

        $x509cert = Utils::formatCert($x509cert);
        $privateKey = Utils::formatPrivateKey($privateKey);

        $sslX509cert = openssl_pkey_get_public($x509cert);
        if (!$sslX509cert) {
            $message = new PsrMessage(
                'The SP public certificate ({use}) is not valid.', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
        }

        $sslPrivateKey = openssl_pkey_get_private($privateKey);
        if (!$sslPrivateKey) {
            $message = new PsrMessage(
                'The SP private key ({use}) is not valid.', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
        }

        if (!$sslX509cert || !$sslPrivateKey) {
            return false;
        }

        $plain = 'Test clés SingleSignOn.';
        $encrypted = '';
        $decrypted = '';

        if (!openssl_public_encrypt($plain, $encrypted, $sslX509cert)) {
            $message = new PsrMessage(
                'Unable to encrypt message with SP public certificate ({use}).', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
            return false;
        }

        if (!openssl_private_decrypt($encrypted, $decrypted, $sslPrivateKey)) {
            $message = new PsrMessage(
                'Unable to decrypt message with SP private key ({use}).', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
            return false;
        }

        if ($decrypted !== $plain) {
            $message = new PsrMessage(
                'An issue occurred during decryption with SP private key ({use}). It may not the good one.', // @translate
                ['use' => $certificateUse]
            );
            $messenger->addError($message);
            return false;
        }

        $message = new PsrMessage(
            'No issue found on SP public certificate and private key ({use}).', // @translate
            ['use' => $certificateUse]
        );
        $messenger->addSuccess($message);

        return true;
    }

    protected function checkX509Certificates(array $x509certificates, ?string $entityUrl = null): array
    {
        $certificates = [];
        foreach ($x509certificates ?? [] as $cerficate) {
            $certificates[] = $this->checkX509Certificate($cerficate, $entityUrl);
        }
        return array_values(array_unique(array_filter($certificates)));
    }

    protected function checkX509Certificate(?string $x509certificate, ?string $entityUrl = null): ?string
    {
        if (!$x509certificate) {
            return null;
        }

        $x509cert = trim($x509certificate);
        if (!$x509cert) {
            return null;
        }

        /** @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
        $services = $this->getServiceLocator();
        $messenger = $services->get('ControllerPluginManager')->get('messenger');

        // Remove windows and apple issues if not done already.
        // Remove tabulations too, not managed by format cert.
        // Anyway, openssl remove header, footer and end of lines automatically.
        $x509cert = Utils::formatCert(strtr($x509cert, ["\t" => '']));

        $sslX509cert = openssl_pkey_get_public($x509cert);
        if (!$sslX509cert) {
            $message = new PsrMessage(
                'The IdP public certificate of "{url}" is not valid.', // @translate
                ['url' => $entityUrl]
            );
            $messenger->addError($message);
            return null;
        }

        $plain = 'Test clés SingleSignOn.';
        $encrypted = '';

        if (!openssl_public_encrypt($plain, $encrypted, $sslX509cert)) {
            $message = new PsrMessage(
                'Unable to encrypt message with IdP public certificate of "{url}".', // @translate
                ['url' => $entityUrl]
            );
            $messenger->addError($message);
            return null;
        }

        $message = new PsrMessage(
            'No issue found on IdP public certificate of "{url}".', // @translate
            ['url' => $entityUrl]
        );
        $messenger->addSuccess($message);

        return Utils::formatCert($x509cert, true);
    }

    /**
     * Create an self-signed x509 certificate with settings or local data.
     *
     * @see https://www.php.net/manual/en/function.openssl-csr-new.php
     */
    protected function createCertificate(array $certificateData): array
    {
        /**
         * @var \Omeka\Settings\Settings $settings
         */
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        // Append some data if they are not filled.
        $dn = [
            'countryName' => '',
            'stateOrProvinceName' => '',
            'localityName' => '',
            'organizationName' => '',
            'organizationalUnitName' => '',
            'commonName' => '',
            'emailAddress' => '',
        ];
        $dn = array_intersect_key($certificateData, $dn);
        if (empty($dn['commonName'])) {
            $commonName = $settings->get('singlesignon_sp_host_name');
            if (!$commonName) {
                $url = $services->get('ViewHelperManager')->get('url');
                $commonName = $url('top', [], ['force_canonical' => true]);
            }
            $dn['commonName'] = parse_url($commonName, PHP_URL_HOST)
                ?: ($_SERVER['SERVER_NAME'] ?? 'localhost');
        }
        if (empty($dn['emailAddress'])) {
            $dn['emailAddress'] = $settings->get('administrator_email', '');
        }
        $dn = array_filter($dn);

        // Create a private key.
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        // Create the Certificate Signing Request.
        $csr = openssl_csr_new($dn, $privateKey, [
            'digest_alg' => 'sha256',
        ]);

        // Self-sign the CSR to create a certificate.
        // The certificate is valid for a century.
        $certificate = openssl_csr_sign($csr, null, $privateKey, 36525, [
            'digest_alg' => 'sha256',
        ]);

        // Export private key and certificate.
        $x509cert = null;
        openssl_x509_export($certificate, $x509cert);
        $readablePrivateKey = null;
        openssl_pkey_export($privateKey, $readablePrivateKey);

        // Free the private key for security.
        if (PHP_VERSION_ID < 80000) {
            openssl_pkey_free($privateKey);
        }

        return [
            $x509cert,
            $readablePrivateKey,
        ];
    }
}
