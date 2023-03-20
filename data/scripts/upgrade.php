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
    $settings->set('singlesignon_sp_metadata_mode', $settings->get('singlesignon_metadata_mode') ?: 'basic');
    $settings->set('singlesignon_idp_attributes_map', $settings->get('singlesignon_attributes_map') ?: []);
    $settings->delete('singlesignon_metadata_mode');
    $settings->delete('singlesignon_attributes_map');
}
