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

        if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.54')) {
            $message = new \Omeka\Stdlib\Message(
                $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
                'Common', '3.4.54'
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

        // At least one fieldset.
        // The list should be zero based to simplify js.
        $data['singlesignon_idps'] = $data['singlesignon_idps'] ?: $config['singlesignon']['config']['singlesignon_idps'];

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
         * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
         * @var \SingleSignOn\Mvc\Controller\Plugin\IdpMetadata $idpMetadata
         */
        $services = $this->getServiceLocator();
        $plugins = $services->get('ControllerPluginManager');
        $settings = $services->get('Omeka\Settings');
        $messenger = $plugins->get('messenger');
        $idpMetadata = $plugins->get('idpMetadata');

        $ssoServices = $settings->get('singlesignon_services') ?: [];

        $idps = $settings->get('singlesignon_idps');

        // Messages are displayed, but data are stored in all cases.
        $this->checkSPConfig();

        $hasError = false;
        $cleanIdps = [];
        foreach (array_values($idps) as $key => $idp) {
            ++$key;
            $entityUrl = $idp['idp_metadata_url'] ?? '';
            $entityId = $idp['idp_entity_id'] ?? '';
            if (!$entityUrl && !$entityId) {
                $hasError = true;
                $message = new PsrMessage(
                    'The IdP #{index} has no url and no id and is not valid.', // @translate
                    ['index' => $key]
                );
                $messenger->addError($message);
                continue;
            }

            $updateMode = $idp['idp_metadata_update_mode'] ?? 'auto';

            // Check if the idp is filled.
            $isFilled = !empty($idp['idp_entity_name'])
                && !empty($idp['idp_x509_certificate'])
                && (!in_array('sso', $ssoServices) || !empty($idp['idp_sso_url']))
                && (!in_array('sls', $ssoServices) || !empty($idp['idp_slo_url']));

            if ($isFilled && $updateMode === 'manual') {
                $cleanIdps[$key] = $idp;
                $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
                $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: (string) $key;
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
                    $cleanIdps[$key] = $idp;
                    continue;
                }
                // Keep some data.
                $idpMeta['idp_entity_name'] = $idpMeta['idp_entity_name'] ?: $idp['idp_entity_name'];
                $idpMeta['idp_attributes_map'] = $idp['idp_attributes_map'];
                $idpMeta['idp_roles_map'] = $idp['idp_roles_map'];
                $idpMeta['idp_user_settings'] = $idp['idp_user_settings'];
                $idpMeta['idp_metadata_update_mode'] = $idp['idp_metadata_update_mode'];
                $idp = $idpMeta;
                $entityId = $idp['idp_entity_id'];
            }

            $entityIdUrl = substr($entityId, 0, 4) !== 'http' ? 'http://' . $entityId : $entityId;
            $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: (string) $key;

            $result = $this->checkX509Certificate($idp['idp_x509_certificate'] ?? null, $idpName);
            if ($result) {
                $idp['idp_x509_certificate'] = $result;
            }

            $cleanIdps[$idpName] = $idp;
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
        if (!$settings->get('singlesignon_append_links_to_login_view')) {
            return;
        }

        /** @var \Laminas\View\Renderer\PhpRenderer $view */
        $view = $event->getTarget();
        echo $view->ssoLoginLinks();
    }

    protected function checkSPConfig(): bool
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

        $x509cert = trim($settings->get('singlesignon_sp_x509_certificate') ?: '');
        $privateKey = trim($settings->get('singlesignon_sp_x509_private_key') ?: '');

        if (!$x509cert && !$privateKey) {
            return true;
        }

        if ($x509cert && !$privateKey) {
            $message = new PsrMessage(
                'The SP public certificate is set, but not the private key.' // @translate
            );
            $messenger->addError($message);
        }

        if (!$x509cert && $privateKey) {
            $message = new PsrMessage(
                'The SP private key is set, but not the public certificate.' // @translate
            );
            $messenger->addError($message);
        }

        // Remove windows and apple issues.
        $spaces = [
            "\r\n" => "\n",
            "\n\r" => "\n",
            "\r" => "\n",
        ];
        $x509cert = str_replace(array_keys($spaces), array_values($spaces), $x509cert);
        $privateKey = str_replace(array_keys($spaces), array_values($spaces), $privateKey);

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
        $spaces = [
            "\r\n" => "\n",
            "\n\r" => "\n",
            "\r" => "\n",
        ];
        $x509cert = str_replace(array_keys($spaces), array_values($spaces), $x509cert);

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
}
