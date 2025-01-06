<?php declare(strict_types=1);

namespace SingleSignOn;

if (!class_exists(\Common\TraitModule::class)) {
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
use Omeka\Module\AbstractModule;
use OneLogin\Saml2\Utils;

/**
 * Single Sign-On
 *
 * @copyright Daniel Berthereau, 2023-2024
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

        if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.63')) {
            $message = new \Omeka\Stdlib\Message(
                $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
                'Common', '3.4.63'
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
    }

    public function getConfigForm(PhpRenderer $view)
    {
        $services = $this->getServiceLocator();

        $settings = $services->get('Omeka\Settings');
        // TODO getConfigModule
        $config = $this->getConfig();
        $defaultSettings = $config['singlesignon']['config'];

        $data = [];
        foreach ($defaultSettings as $name => $value) {
            $val = $settings->get($name, is_array($value) ? [] : null);
            $data[$name] = $val;
        }

        // Remove the federated idps from the list of idps to keep only the
        // manually defined ones.
        $data['singlesignon_idps'] = array_filter($data['singlesignon_idps'], fn ($v) => empty($v['federation_url']));

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

        $ssoServices = $settings->get('singlesignon_services') ?: [];

        // For security, forbid admin roles for new user.
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

        // Messages are displayed, but data are stored in all cases.
        $this->checkConfigSP();

        $this->checkConfigFederation();

        // Check and finalize federation.
        $federation = $settings->get('singlesignon_federation');
        if ($federation) {
            $this->prepareFederation($federation);
        }

        // Check and finalize idps.
        $idps = $settings->get('singlesignon_idps');

        $hasError = false;
        $cleanIdps = [];
        foreach (array_values($idps) as $key => $idp) {
            ++$key;
            $federationUrl = $idp['federation_url'] ?? '';
            $entityUrl = $idp['metadata_url'] ?? '';
            $entityId = $idp['entity_id'] ?? '';
            if ($federationUrl) {
                if (!$entityId) {
                    $hasError = true;
                    $message = new PsrMessage(
                        'The federated IdP #{index} has no id and is not valid.', // @translate
                        ['index' => $key]
                    );
                    $messenger->addError($message);
                    continue;
                }
            } elseif (!$entityId && !$entityUrl) {
                $hasError = true;
                $message = new PsrMessage(
                    'The IdP #{index} has no url and no id and is not valid.', // @translate
                    ['index' => $key]
                );
                $messenger->addError($message);
                continue;
            }

            $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
            $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;

            // Don't check the idps of the federation.
            if ($federationUrl) {
                // Warning: a federated idp should not override a manual one.
                // Normally, single idps are checked first in the list.
                $cleanIdps[$entityId] ??= $idp;
                continue;
            }

            $updateMode = $idp['metadata_update_mode'] ?? 'auto';

            // Check if the idp is filled.
            $isFilled = !empty($idp['entity_name'])
                && !empty($idp['x509_certificate'])
                && (!in_array('sso', $ssoServices) || !empty($idp['sso_url']))
                && (!in_array('sls', $ssoServices) || !empty($idp['slo_url']));

            if ($isFilled && $updateMode === 'manual') {
                $cleanIdps[$entityId ?: $idpName] = $idp;
                $message = new PsrMessage(
                    'The idp "{idp}" was manually filled and is not checked neither updated.', // @translate
                    ['idp' => $idpName]
                );
                $messenger->addWarning($message);
                continue;
            }

            if ($entityUrl) {
                $idpMeta = $idpMetadata($entityUrl, true);
                if (!$idpMeta) {
                    // Message is already prepared.
                    $cleanIdps[$entityId ?: $idpName] = $idp;
                    continue;
                }
                // Keep some data.
                $idpMeta['entity_name'] = $idpMeta['entity_name'] ?: $idp['entity_name'];
                $idpMeta['attributes_map'] = $idp['attributes_map'];
                $idpMeta['roles_map'] = $idp['roles_map'];
                $idpMeta['user_settings'] = $idp['user_settings'];
                $idpMeta['metadata_update_mode'] = $idp['metadata_update_mode'];
                if ($updateMode === 'auto_except_id') {
                    $idpMeta['entity_id'] = $entityId;
                }
                $idp = $idpMeta;
                $entityId = $idp['entity_id'];
                $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
                $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;
            }

            $result = $this->checkX509Certificate($idp['x509_certificate'] ?? null, $idpName);
            if ($result) {
                $idp['x509_certificate'] = $result;
            }

            // Normally not possible.
            if (!$entityId) {
                $cleanIdps[$idpName] = $idp;
                $message = new PsrMessage(
                    'The idp "{idp}" seems to be invalid and has no id.', // @translate
                    ['idp' => $idpName]
                );
                $messenger->addWarning($message);
                continue;
            }

            $cleanIdps[$entityId] = $idp;
        }

        $settings->set('singlesignon_idps', $cleanIdps);

        return !$hasError;
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
                'A federation is specified and a list of idps too. The idps defined manually will overwrite the federation ones with the same name.', // @ŧranslate
            ));
            return false;
        }

        return true;
    }

    protected function checkConfigSP(): bool
    {
        /**
         * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
         * @var \Omeka\Settings\Settings $settings
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $messenger = $plugins->get('messenger');

        $basePath = $settings->get('singlesignon_sp_cert_path');
        $x509cert = trim($settings->get('singlesignon_sp_x509_certificate') ?: '');
        $privateKey = trim($settings->get('singlesignon_sp_x509_private_key') ?: '');

        if (!$x509cert && !$privateKey) {
            if ($basePath) {
                $x509certFilePath = $basePath . '/certs/sp.crt';
                $x509cert = file_exists($x509certFilePath) || !is_readable($x509certFilePath) || !filesize($x509certFilePath)
                    ? file_get_contents($x509certFilePath)
                    : '';
                $privateKeyPath = $basePath . '/certs/sp.key';
                $privateKey = file_exists($privateKeyPath) || !is_readable($privateKeyPath) || !filesize($privateKeyPath)
                    ? file_get_contents($privateKeyPath)
                    : '';
                if (!$x509cert || !$privateKey) {
                    $message = new PsrMessage(
                        'A path is set for the certificate, but it does not contain a directory "certs" with files "sp.crt" and "sp.key".' // @translate
                    );
                    $messenger->addError($message);
                }
            } else {
                return true;
            }
        } elseif ($x509cert && !$privateKey) {
            $message = new PsrMessage(
                'The SP public certificate is set, but not the private key.' // @translate
            );
            $messenger->addError($message);
        } elseif (!$x509cert && $privateKey) {
            $message = new PsrMessage(
                'The SP private key is set, but not the public certificate.' // @translate
            );
            $messenger->addError($message);
        }

        if ($basePath && ($x509cert || $privateKey)) {
            $message = new PsrMessage(
                'You cannot set a path to the certificate and provide them in fields at the same time.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        // Remove windows and apple issues.
        $x509cert = str_replace(["\r\n", "\n\r", "\r"], "\n", $x509cert);
        $privateKey = str_replace(["\r\n", "\n\r", "\r"], "\n", $privateKey);

        // Clean keys.
        $x509cert = Utils::formatCert($x509cert, true);
        $privateKey = Utils::formatPrivateKey($privateKey, true);
        $settings->set('singlesignon_sp_x509_certificate', $x509cert);
        $settings->set('singlesignon_sp_x509_private_key', $privateKey);

        $x509cert = Utils::formatCert($x509cert);
        $privateKey = Utils::formatPrivateKey($privateKey);

        $sslX509cert = openssl_pkey_get_public($x509cert);
        if (!$sslX509cert) {
            $message = new PsrMessage(
                'The SP public certificate is not valid.' // @translate
            );
            $messenger->addError($message);
        }

        $sslPrivateKey = openssl_pkey_get_private($privateKey);
        if (!$sslPrivateKey) {
            $message = new PsrMessage(
                'The SP private key is not valid.' // @translate
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
                'Unable to encrypt message with SP public certificate.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        if (!openssl_private_decrypt($encrypted, $decrypted, $sslPrivateKey)) {
            $message = new PsrMessage(
                'Unable to decrypt message with SP private key.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        if ($decrypted !== $plain) {
            $message = new PsrMessage(
                'An issue occurred during decryption with SP private key. It may not the good one.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        $message = new PsrMessage(
            'No issue found on SP public certificate and private key.' // @translate
        );
        $messenger->addSuccess($message);

        return true;
    }

    protected function checkX509Certificate(?string $x509Certificate, ?string $idpName = null): ?string
    {
        if (!$x509Certificate) {
            return null;
        }

        $x509cert = trim($x509Certificate);
        if (!$x509cert) {
            return true;
        }

        /** @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger */
        $services = $this->getServiceLocator();
        $messenger = $services->get('ControllerPluginManager')->get('messenger');

        // Remove windows and apple issues.
        $x509cert = str_replace(["\r\n", "\n\r", "\r"], "\n", $x509cert);

        $x509cert = Utils::formatCert($x509cert);

        $sslX509cert = openssl_pkey_get_public($x509cert);
        if (!$sslX509cert) {
            $message = new PsrMessage(
                'The IdP public certificate of "{idp}" is not valid.', // @translate
                ['idp' => $idpName]
            );
            $messenger->addError($message);
            return null;
        }

        $plain = 'Test clés SingleSignOn.';
        $encrypted = '';

        if (!openssl_public_encrypt($plain, $encrypted, $sslX509cert)) {
            $message = new PsrMessage(
                'Unable to encrypt message with IdP public certificate of "{idp}".', // @translate
                ['idp' => $idpName]
            );
            $messenger->addError($message);
            return null;
        }

        $message = new PsrMessage(
            'No issue found on IdP public certificate of "{idp}".', // @translate
            ['idp' => $idpName]
        );
        $messenger->addSuccess($message);

        return Utils::formatCert($x509cert, true);
    }

    protected function prepareFederation(string $federation): bool
    {
        $services = $this->getServiceLocator();
        $config = $services->get('Config');
        $settings = $services->get('Omeka\Settings');

        $federations = $config['singlesignon']['federations'];
        if (!isset($federations[$federation])) {
            return false;
        }

        $federationUrl = $federations[$federation];

        /**
         * @var \SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata $ssoFederationMetadata
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $ssoFederationMetadata = $plugins->get('ssoFederationMetadata');

        $result = $ssoFederationMetadata($federationUrl, null, true);
        if ($result === null) {
            return false;
        }

        usort($result, fn ($idpA, $idpB) => strcasecmp($idpA['entity_name'], $idpB['entity_name']));

        // Store the federated idps and the locally defined idps in a single
        // place to simplify interface and management.
        // The local idps may override the federated ones.
        // Keep them first.

        $idps = $settings->get('singlesignon_idps');
        $idps = array_filter($idps, fn ($v) => empty($v['federation_url']));

        $idps = $idps + $result;

        $settings->set('singlesignon_idps', $idps);

        return true;
    }
}
