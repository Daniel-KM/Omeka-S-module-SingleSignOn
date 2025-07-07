<?php

declare(strict_types=1);

namespace SingleSignOn;

return [
    'service_manager' => [
        'factories' => [
            'Omeka\AuthenticationService' => Service\AuthenticationServiceFactory::class,
        ],
    ],
    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
        ],
    ],
    'view_helpers' => [
        'invokables' => [
            'ssoLoginLinks' => View\Helper\SsoLoginLinks::class,
        ],
        'factories' => [
            'isSsoUser' => Service\ViewHelper\IsSsoUserFactory::class,
        ],
    ],
    'block_layouts' => [
        'invokables' => [
            'ssoLoginLinks' => Site\BlockLayout\SsoLoginLinks::class,
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\IdpFieldset::class => Form\IdpFieldset::class,
            Form\SsoLoginLinksFieldset::class => Form\SsoLoginLinksFieldset::class,
        ],
        'factories' => [
            Form\ConfigForm::class => Service\Form\ConfigFormFactory::class,
        ],
    ],
    'controllers' => [
        'factories' => [
            Controller\SsoController::class => Service\Controller\SsoControllerFactory::class,
        ],
    ],
    'controller_plugins' => [
        'factories' => [
            'idpMetadata' => Service\ControllerPlugin\IdpMetadataFactory::class,
            'isSsoUser' => Service\ControllerPlugin\IsSsoUserFactory::class,
            'ssoFederationMetadata' => Service\ControllerPlugin\SsoFederationMetadataFactory::class,
        ],
    ],
    'router' => [
        'routes' => [
            'sso' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/sso[/:action][/:idp]',
                    'constraints' => [
                        'action' => 'metadata|login|acs|logout|sls',
                        'idp' => '[a-zA-Z0-9_.:-]+',
                    ],
                    'defaults' => [
                        '__NAMESPACE__' => 'SingleSignOn\Controller',
                        'controller' => Controller\SsoController::class,
                        'action' => 'metadata',
                    ],
                ],
            ],
        ],
    ],
    'singlesignon' => [
        'config' => [
            'singlesignon_services' => [
                // Login.
                'sso',
                // Logout.
                'sls',
                // Register.
                'jit',
                // Update user name and settings on login.
                'update_user_name',
                'update_user_settings',
            ],

            // Default role is the lowest one (guest or researcher).
            'singlesignon_role_default' => null,
            'singlesignon_groups_default' => null,

            'singlesignon_append_links_to_login_view' => null,
            'singlesignon_redirect' => null,

            'singlesignon_sp_entity_id' => '',
            'singlesignon_sp_host_name' => '',
            'singlesignon_sp_metadata_content_type' => 'saml',
            'singlesignon_sp_metadata_disposition' => 'inline',
            'singlesignon_sp_metadata_mode' => 'standard',
            'singlesignon_sp_name_id_format' => '',
            'singlesignon_sp_sign_x509_path' => '',
            'singlesignon_sp_sign_x509_certificate' => '',
            'singlesignon_sp_sign_x509_private_key' => '',
            'singlesignon_sp_sign_x509_certificate_data' => '',
            'singlesignon_sp_crypt_x509_path' => '',
            'singlesignon_sp_crypt_x509_certificate' => '',
            'singlesignon_sp_crypt_x509_private_key' => '',
            'singlesignon_sp_crypt_x509_certificate_data' => '',

            // The config of the federation is merged with the single idps in
            // "singlesignon_idps".
            // The difference is the presence of the key "federation_url", that
            // replaces the key "metadata_url".
            'singlesignon_federation' => null,

            // The config manages multiple idp services.
            // In Omeka, they are all stored in one setting for now.
            'singlesignon_idps' => [
                [
                    'metadata_update_mode' => 'auto',
                    'metadata_use_federation_data' => false,
                    'metadata_keep_entity_id' => false,
                    'metadata_url' => '',
                    'entity_id' => '',
                    'entity_name' => '',
                    // This value is stored automatically from the sso url in
                    // order to manage idps that use a urn as id.
                    // 'host' => '',
                    'sso_url' => '',
                    'slo_url' => '',
                    // Shibboleth may use multiple signing certificates: back channel,
                    // front channel, etc. So they should be all stored and checked.
                    'sign_x509_certificates' => [],
                    'crypt_x509_certificates' => [],
                    // The two following keys are kept to manage the form, but
                    // values are moved to array.
                    'sign_x509_certificate' => '',
                    'crypt_x509_certificate' => '',
                    'attributes_map' => [
                        'mail' => 'email',
                        'displayName' => 'name',
                        /*
                        'role' => 'role',
                        'memberOf' => 'role',
                        'language' => 'locale',
                        'anotherKey' => 'userprofile_param',
                        'yetAnotherKey' => 'a_user_setting_key',
                        */
                    ],
                    // For security, it is not recommended to map to admin roles,
                    // but to update user manually in admin board.
                    'roles_map' => [
                        // '' => 'global_admin',
                        // '' => 'site_admin',
                        // '' => 'editor',
                        // '' => 'reviewer',
                        // '' => 'author',
                        // '' => 'researcher',
                        // These roles require modules.
                        // '' => 'guest',
                        // '' => 'annotator',
                    ],
                    // Keys to store as user setting when the user is created.
                    // Warning: these values are not updated automatically.
                    'user_settings' => [
                        // Static keys.
                        // 'locale' => 'fr',
                        // 'guest_agreed_terms' => true,
                        // 'userprofile_key' => 'value',
                    ],
                ],
            ],
        ],
        'block_settings' => [
            'ssoLoginLinks' => [
                'internal' => false,
                'selector' => false,
            ],
        ],
        'user_settings' => [
            // Hidden settings to store the idp name.
            // More keys can be set during login, according to config.
            'connection_authenticator' => null,
            'connection_idp' => null,
            'connection_last' => null,
        ],
        'federations' => [
            // File "main idps" is the most useful for the module.
            'Renater'
                => 'https://pub.federation.renater.fr/metadata/renater/main/main-idps-renater-metadata.xml',
            'Test: Renater'
                => 'https://pub.federation.renater.fr/metadata/test/preview/preview-idps-test-metadata.xml',
            // Urls and local paths are allowed.
        ],
    ],
    'authentication' => [
        // Warning: check your idp access first, because when set true,
        // all current locally logged users will be logged out.
        'forbid_local_login' => false,
        // Unless this option is false: in that case, current sessions are kept.
        'logout_logged_users' => false,
    ],
];
