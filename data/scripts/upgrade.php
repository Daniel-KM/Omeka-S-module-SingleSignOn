<?php declare(strict_types=1);

namespace SingleSignOn;

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
$connection = $services->get('Omeka\Connection');
$messenger = $plugins->get('messenger');
$entityManager = $services->get('Omeka\EntityManager');

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

    $message = new Message(
        'It is possible now to manage multipe IdPs.' // @translate
    );
    $messenger->addSuccess($message);
}
