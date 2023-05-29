<?php declare(strict_types=1);

namespace SingleSignOn;

return [
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
            Form\IdpFieldset::class => Form\IdpFieldset::class,
        ],
    ],
    'controllers' => [
        'factories' => [
            Controller\SsoController::class => Service\Controller\SsoControllerFactory::class,
        ],
    ],
    'router' => [
        'routes' => [
            'sso' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/sso[/:action]',
                    'constraints' => [
                        'action' => 'metadata|login|acs|logout|sls',
                    ],
                    'defaults' => [
                        '__NAMESPACE__' => 'SingleSignOn\Controller',
                        'controller' => Controller\SsoController::class,
                        'action' => 'metadata',
                    ],
                ],
            ],
            'sso-id' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/sso/:idp[/:action]',
                    'constraints' => [
                        'idp' => '[a-zA-Z0-9_.-]+',
                        'action' => 'login|acs|logout|sls',
                    ],
                    'defaults' => [
                        '__NAMESPACE__' => 'SingleSignOn\Controller',
                        'controller' => Controller\SsoController::class,
                        'action' => 'login',
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
                    'idp_entity_id' => '',
                    'idp_sso_url' => '',
                    'idp_slo_url' => '',
                    'idp_x509_certificate' => '',
                    'idp_attributes_map' => [
                        'mail' => 'email',
                        'displayName' =>'name',
                        /*
                        'role' => 'role',
                        */
                    ],
                ],
            ],
        ],
    ],
];
