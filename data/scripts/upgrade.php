<?php declare(strict_types=1);

namespace SingleSignOn;

use Common\Stdlib\PsrMessage;
use Omeka\Stdlib\Message;

/**
 * @var Module $this
 * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
 * @var string $newVersion
 * @var string $oldVersion
 *
 * @var \Omeka\Api\Manager $api
 * @var \Omeka\Settings\Settings $settings
 * @var \Doctrine\DBAL\Connection $connection
 * @var \Doctrine\ORM\EntityManager $entityManager
 * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
 */
$plugins = $services->get('ControllerPluginManager');
$api = $plugins->get('api');
$settings = $services->get('Omeka\Settings');
$translate = $plugins->get('translate');
$connection = $services->get('Omeka\Connection');
$messenger = $plugins->get('messenger');
$entityManager = $services->get('Omeka\EntityManager');

if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.54')) {
    $message = new Message(
        $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
        'Common', '3.4.54'
    );
    throw new \Omeka\Module\Exception\ModuleCannotInstallException((string) $message);
}

if (version_compare($oldVersion, '3.4.3', '<')) {
    $settings->set('singlesignon_sp_metadata_mode', $settings->get('singlesignon_metadata_mode') ?: 'standard');
    $settings->set('singlesignon_idp_attributes_map', $settings->get('singlesignon_attributes_map') ?: []);
    $settings->delete('singlesignon_metadata_mode');
    $settings->delete('singlesignon_attributes_map');
}

if (version_compare($oldVersion, '3.4.5', '<')) {
    $idp = [
        'idp_entity_id' => $settings->get('singlesignon_idp_entity_id', ''),
        'idp_sso_url' => $settings->get('singlesignon_idp_sso_url', ''),
        'idp_slo_url' => $settings->get('singlesignon_idp_slo_url', ''),
        'idp_x509_certificate' => $settings->get('singlesignon_idp_x509_certificate', ''),
        'idp_attributes_map' => $settings->get('singlesignon_idp_attributes_map', []),
    ];
    $entityId = $idp['idp_entity_id'] ?? '';
    if (substr($entityId, 0, 4) !== 'http') {
        $entityId = 'http://' . $entityId;
    }
    $idpName = parse_url($entityId, PHP_URL_HOST) ?: 0;
    $settings->set('singlesignon_idps', [$idpName => $idp]);

    $settings->delete('singlesignon_idp_entity_id');
    $settings->delete('singlesignon_idp_sso_url');
    $settings->delete('singlesignon_idp_slo_url');
    $settings->delete('singlesignon_idp_x509_certificate');
    $settings->delete('singlesignon_idp_attributes_map');

    $message = new PsrMessage(
        'It is now possible to manage multiple IdPs.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.6', '<')) {
    $message = new PsrMessage(
        'It is now possible to config and update IdPs automatically with IdP metadata url.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.7', '<')) {
    $message = new PsrMessage(
        'It is now possible to map IdP and Omeka roles and settings.' // @translate
    );
    $messenger->addSuccess($message);
}
