<?php declare(strict_types=1);

namespace SingleSignOn;

return [
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
        ],
    ],
    'controllers' => [
        'factories' => [
            'SingleSignOn\Controller\Sso' => Service\Controller\SsoControllerFactory::class,
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
                        'controller' => 'Sso',
                        'action' => 'metadata',
                    ],
                ],
            ],
        ],
    ],
    'singlesignon' => [
        'config' => [
            'singlesignon_services' => [
                // login.
                'sso',
                // logout.
                // 'sls',
                // register.
                // 'jit',
            ],
            'singlesignon_idp_entity_id' => '',
            'singlesignon_idp_sso_url' => '',
            'singlesignon_idp_slo_url' => '',
            'singlesignon_idp_x509_certificate' => '',
            'singlesignon_attributes_map' => [
                /*
                // Friendly
                'mail' => 'email',
                'displayName' =>'name',
                'role' => 'role',
                */
            ],
        ],
    ],
];
