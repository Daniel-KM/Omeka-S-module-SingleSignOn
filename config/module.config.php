<?php declare(strict_types=1);

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
        'invokables' => [
            'idpMetadata' => Mvc\Controller\Plugin\IdpMetadata::class,
            'ssoFederationMetadata' => Mvc\Controller\Plugin\SsoFederationMetadata::class,
        ],
        'factories' => [
            'isSsoUser' => Service\ControllerPlugin\IsSsoUserFactory::class,
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
                        'idp' => '[a-zA-Z0-9_.-]+',
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
                // 'sls',
                // Register.
                // 'jit',
                // Update user name.
                // 'update',
            ],

            // Default role is the lowest one (guest or researcher).
            'singlesignon_role_default' => null,

            'singlesignon_append_links_to_login_view' => false,

            'singlesignon_sp_metadata_content_type' => 'saml',
            'singlesignon_sp_metadata_disposition' => 'inline',
            'singlesignon_sp_metadata_mode' => 'standard',
            'singlesignon_sp_name_id_format' => '',
            'singlesignon_sp_cert_path' => '',
            'singlesignon_sp_x509_certificate' => '',
            'singlesignon_sp_x509_private_key' => '',

            // The config of the federation is merged with the single idps in
            // "singlesignon_idps".
            // The difference is the presence of the key "federation_url", that
            // replaces the key "idp_metadata_url".
            'singlesignon_federation' => null,

            // The config manages multiple idp services.
            // In Omeka, they are all stored in one setting for now.
            'singlesignon_idps' => [
                [
                    'idp_metadata_url' => '',
                    'idp_entity_id' => '',
                    'idp_entity_name' => '',
                    'idp_sso_url' => '',
                    'idp_slo_url' => '',
                    'idp_x509_certificate' => '',
                    'idp_attributes_map' => [
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
                    'idp_roles_map' => [
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
                    'idp_user_settings' => [
                        // Static keys.
                        // 'locale' => 'fr',
                        // 'guest_agreed_terms' => true,
                        // 'userprofile_key' => 'value',
                    ],
                    'idp_metadata_update_mode' => 'auto',
                ],
            ],
        ],
        'block_settings' => [
            'ssoLoginLinks' => [
                'heading' => '',
                'internal' => false,
                'template' => '',
            ],
        ],
        'federations' => [
            // File "main idps" is the most useful for the module.
            'Renater'
                => 'https://pub.federation.renater.fr/metadata/renater/main/main-idps-renater-metadata.xml',
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
