<?php declare(strict_types=1);

namespace SingleSignOn;

if (!class_exists(\Generic\AbstractModule::class)) {
    require file_exists(dirname(__DIR__) . '/Generic/AbstractModule.php')
        ? dirname(__DIR__) . '/Generic/AbstractModule.php'
        : __DIR__ . '/src/Generic/AbstractModule.php';
}

use Generic\AbstractModule;
use Laminas\ModuleManager\ModuleManager;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\Mvc\MvcEvent;
use OneLogin\Saml2\Utils;

/**
 * Single Sign-On
 *
 * @copyright Daniel Berthereau, 2023
 * @license http://www.cecill.info/licences/Licence_CeCILL_V2.1-en.txt
 */
class Module extends AbstractModule
{
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
                'SingleSignOn\Controller\Sso'
            );
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $result = parent::handleConfigForm($controller);
        if (!$result) {
            return false;
        }

        // Messages are displayed, but data are stored in all cases.
        $this->checkSPConfig();

        return true;
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
            $message = new \Omeka\Stdlib\Message(
                'The SP public certificate is set, but not the private key.' // @translate
            );
            $messenger->addError($message);
        }

        if (!$x509cert && $privateKey) {
            $message = new \Omeka\Stdlib\Message(
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
            $message = new \Omeka\Stdlib\Message(
                'The SP public certificate is not valid.' // @translate
            );
            $messenger->addError($message);
        }

        $sslPrivateKey = openssl_pkey_get_private($privateKey);
        if (!$sslPrivateKey) {
            $message = new \Omeka\Stdlib\Message(
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
            $message = new \Omeka\Stdlib\Message(
                'Unable to encrypt message with SP public certificate.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        if (!openssl_private_decrypt($encrypted, $decrypted, $sslPrivateKey)) {
            $message = new \Omeka\Stdlib\Message(
                'Unable to decrypt message with SP private key.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        if ($decrypted !== $plain) {
            $message = new \Omeka\Stdlib\Message(
                'An issue occurred during decryption with SP private key. It may not the good one.' // @translate
            );
            $messenger->addError($message);
            return false;
        }

        $message = new \Omeka\Stdlib\Message(
            'No issue found on SP public certificate and private key.' // @translate
        );
        $messenger->addSuccess($message);

        return true;
    }
}
