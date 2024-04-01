<?php declare(strict_types=1);

namespace SingleSignOn;

return [
    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
        ],
    ],
    'view_helpers' => [
        'invokables' => [
            'ssoLoginLinks' => View\Helper\SsoLoginLinks::class,
        ],
    ],
    'block_layouts' => [
        'invokables' => [
            'ssoLoginLinks' => Site\BlockLayout\SsoLoginLinks::class,
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
            Form\IdpFieldset::class => Form\IdpFieldset::class,
            Form\SsoLoginLinksFieldset::class => Form\SsoLoginLinksFieldset::class,
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

            'singlesignon_append_links_to_login_view' => false,

            'singlesignon_sp_metadata_content_type' => 'saml',
            'singlesignon_sp_metadata_disposition' => 'inline',
            'singlesignon_sp_metadata_mode' => 'standard',
            'singlesignon_sp_name_id_format' => '',
            'singlesignon_sp_cert_path' => '',
            'singlesignon_sp_x509_certificate' => '',
            'singlesignon_sp_x509_private_key' => '',

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
    ],
];
