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
 * @var \Omeka\View\Helper\Url $url
 * @var \Laminas\Log\Logger $logger
 * @var \Omeka\Settings\Settings $settings
 * @var \Laminas\I18n\View\Helper\Translate $translate
 * @var \Doctrine\DBAL\Connection $connection
 * @var \Laminas\Mvc\I18n\Translator $translator
 * @var \Doctrine\ORM\EntityManager $entityManager
 * @var \Omeka\Settings\SiteSettings $siteSettings
 * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
 */
$plugins = $services->get('ControllerPluginManager');
$url = $services->get('ViewHelperManager')->get('url');
$api = $plugins->get('api');
$logger = $services->get('Omeka\Logger');
$settings = $services->get('Omeka\Settings');
$translate = $plugins->get('translate');
$translator = $services->get('MvcTranslator');
$connection = $services->get('Omeka\Connection');
$messenger = $plugins->get('messenger');
$siteSettings = $services->get('Omeka\Settings\Site');
$entityManager = $services->get('Omeka\EntityManager');

if (!method_exists($this, 'checkModuleActiveVersion') || !$this->checkModuleActiveVersion('Common', '3.4.70')) {
    $message = new Message(
        $translate('The module %1$s should be upgraded to version %2$s or later.'), // @translate
        'Common', '3.4.70'
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

if (version_compare($oldVersion, '3.4.11', '<')) {
    $activeSsoServices = $settings->get('singlesignon_services') ?: [];
    $updatePos = array_search('update', $activeSsoServices);
    if ($updatePos !== false) {
        unset($activeSsoServices[$updatePos]);
        $activeSsoServices[] = 'update_user_name';
        $settings->set('singlesignon_services', $activeSsoServices);
    }

    $message = new PsrMessage(
        'It is now possible to set an IdP manually. Warning: the certificate of IdP set manually will not be updated automatically.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.13', '<')) {
    $message = new PsrMessage(
        'It is now possible to force login via SSO, so to disallow local login.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'It is now possible to define a default role.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.14', '<')) {
    // Check themes that use "$heading" and templates in block.
    $logger = $services->get('Omeka\Logger');
    $pageRepository = $entityManager->getRepository(\Omeka\Entity\SitePage::class);

    $viewHelpers = $services->get('ViewHelperManager');
    $escape = $viewHelpers->get('escapeHtml');
    $hasBlockPlus = $this->isModuleActive('BlockPlus');

    $pagesUpdated = [];
    $pagesUpdated2 = [];
    foreach ($pageRepository->findAll() as $page) {
        $pageSlug = $page->getSlug();
        $siteSlug = $page->getSite()->getSlug();
        $position = 0;
        foreach ($page->getBlocks() as $block) {
            $block->setPosition(++$position);
            $layout = $block->getLayout();
            if ($layout !== 'ssoLoginLinks') {
                continue;
            }
            $data = $block->getData() ?: [];

            $heading = $data['heading'] ?? '';
            if (strlen($heading)) {
                $b = new \Omeka\Entity\SitePageBlock();
                $b->setPage($page);
                $b->setPosition(++$position);
                if ($hasBlockPlus) {
                    $b->setLayout('heading');
                    $b->setData([
                        'text' => $heading,
                        'level' => 2,
                    ]);
                } else {
                    $b->setLayout('html');
                    $b->setData([
                        'html' => '<h2>' . $escape($heading) . '</h2>',
                    ]);
                }
                $entityManager->persist($b);
                $block->setPosition(++$position);
                $pagesUpdated[$siteSlug][$pageSlug] = $pageSlug;
            }
            unset($data['heading']);

            $template = $data['template'] ?? '';
            $layoutData = $block->getLayoutData() ?? [];
            $existingTemplateName = $layoutData['template_name'] ?? null;
            $templateName = pathinfo($template, PATHINFO_FILENAME);
            $templateCheck = 'sso-login-link';
            if ($templateName
                && $templateName !== $templateCheck
                && (!$existingTemplateName || $existingTemplateName === $templateCheck)
            ) {
                $layoutData['template_name'] = $templateName;
                $pagesUpdated2[$siteSlug][$pageSlug] = $pageSlug;
            }
            unset($data['template']);

            $block->setData($data);
            $block->setLayoutData($layoutData);
        }
    }

    $entityManager->flush();

    if ($pagesUpdated) {
        $result = array_map('array_values', $pagesUpdated);
        $message = new PsrMessage(
            'The settings "heading" was removed from block Sso login links. New blocks "Heading" or "Html" were prepended to all blocks that had a filled heading. You may check pages for styles: {json}', // @translate
            ['json' => json_encode($result, 448)]
        );
        $messenger->addWarning($message);
        $logger->warn($message->getMessage(), $message->getContext());
    }

    if ($pagesUpdated2) {
        $result = array_map('array_values', $pagesUpdated2);
        $message = new PsrMessage(
            'The setting "template" was moved to the new block layout settings available since Omeka S v4.1. You may check pages for styles: {json}', // @translate
            ['json' => json_encode($result, 448)]
        );
        $messenger->addWarning($message);
        $logger->warn($message->getMessage(), $message->getContext());

        $message = new PsrMessage(
            'The template files for the block Sso login links should be moved from "view/common/block-layout" to "view/common/block-template" in your themes. You may check your themes for pages: {json}', // @translate
            ['json' => json_encode($result, 448)]
        );
        $messenger->addError($message);
        $logger->warn($message->getMessage(), $message->getContext());
    }

    $message = new PsrMessage(
        'It is now possible to define a federation of idps like Renater instead of individual idps.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.16', '<')) {
    $idps = $settings->get('singlesignon_idps', []);
    foreach ($idps as $idpName => &$idp) {
        // Set the short id.
        $entityIdUrl = $idp['idp_metadata_url'] ?: '';
        $entityId = $idp['idp_entity_id'] ?: $idpName;
        $idpName = parse_url($entityIdUrl, PHP_URL_HOST) ?: $entityId;
        $idp['idp_entity_short_id'] = $idpName;
        // Set the host.
        $ssoUrl = $idp['idp_sso_url'] ?? null;
        $idp['idp_host'] = $ssoUrl
            ? parse_url($ssoUrl, PHP_URL_HOST)
            : null;
    }
    unset($idp);
    $settings->set('singlesignon_idps', $idps);

    // Remove "idp_" from keys.
    foreach ($idps as $idpName => $idp) {
        $idpNew = [];
        foreach ($idp as $key => $value) {
            $idpNew[mb_substr($key, 0, 4) === 'idp_' ? mb_substr($key, 4) : $key] = $value;
        }
        $idps[$idpName] = $idpNew;
    }
    $settings->set('singlesignon_idps', $idps);

    $message = new PsrMessage(
        'It is now possible to define a specific entity id (default is the url of the site).' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'It is now possible to create the x509 certificate of the SP.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'It is now possible to manage IdPs with a urn as entity id.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'A new option allows to replace the host domain used by Omeka as internal SP server with the host name used in public.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'A new option allows to set the page to redirect after login.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'A new option allows to set groups for new users (module Group).' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.17', '<')) {
    $renamedKeys = [
        'singlesignon_sp_cert_path' => 'singlesignon_sp_sign_x509_path',
        'singlesignon_sp_x509_certificate' => 'singlesignon_sp_sign_x509_certificate',
        'singlesignon_sp_x509_private_key' => 'singlesignon_sp_sign_x509_private_key',
        'singlesignon_sp_x509_certificate_data' => 'singlesignon_sp_sign_x509_certificate_data',
    ];
    foreach ($renamedKeys as $oldK => $newK) {
        if ($settings->get($newK) === null) {
            $settings->set($newK, $settings->get($oldK));
        }
        $settings->delete($oldK);
    }

    $idps = $settings->get('singlesignon_idps', []);
    $newIdps = [];
    foreach ($idps as $idpName => $idp) {
        if (empty($idp['federation_url'])) {
            $idp = $this->completeIdpData($idp) + $idp;
        }
        $idp['sign_x509_certificate'] = $idp['x509_certificate'] ?? $idp['sign_x509_certificate'] ?? null;
        unset($idp['x509_certificate']);
        $key = $idp['entity_id'] ?: $idp['entity_short_id'] ?: $idp['host'];
        $newIdps[$key] = $idp;
    }
    unset($idp);
    $settings->set('singlesignon_idps', $newIdps);

    $message = new PsrMessage(
        'A new option allows to store the certificate used to encrypt process, not only to sign in.' // @translate
    );
    $messenger->addSuccess($message);
}

if (version_compare($oldVersion, '3.4.18', '<')) {
    $idps = $settings->get('singlesignon_idps', []);
    $newIdps = [];
    foreach ($idps as $idpName => $idp) {
        $idp['sign_x509_certificates'] ??= empty($idp['sign_x509_certificate']) ? [] : [$idp['sign_x509_certificate']];
        $idp['crypt_x509_certificates'] ??= empty($idp['crypt_x509_certificate']) ? [] : [$idp['crypt_x509_certificate']];
        $newIdps[$idpName] = $idp;
    }
    unset($idp);
    $settings->set('singlesignon_idps', $newIdps);

    $message = new PsrMessage(
        'Multiple signing and encryption certificates are now managed. The compatibility with Shibboleth was improved. For Shibboleth, you may need to set an encryption certificate for the sp.' // @translate
    );
    $messenger->addSuccess($message);

    $message = new PsrMessage(
        'To upgrade the config, you must go to the {link}config form{link_end} and submit it manually.', // @translate
        [
            'link' => sprintf('<a href="%s">', $url('admin/default', ['controller' => 'module', 'action' => 'configure'], ['query' => ['id' => 'SingleSignOn']])),
            'link_end' => '</a>',
        ]
    );
    $message->setEscapeHtml(false);
    $messenger->addWarning($message);
}

if (version_compare($oldVersion, '3.4.20', '<')) {
    $message = new PsrMessage(
        'A new option allows to update settings from idp attributes on login.' // @translate
    );
    $messenger->addSuccess($message);
}
