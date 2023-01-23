<?php declare(strict_types=1);

namespace SingleSignOn;

return [
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
        ],
    ],
    'singlesignon' => [
        'config' => [
            'singlesignon_idp_entity_id' => '',
            'singlesignon_idp_sso_url' => '',
            'singlesignon_idp_slo_url' => '',
            'singlesignon_idp_x509_certificate' => '',
            'singlesignon_attributes_map' => [
                'mail' => 'email',
                'fullname' =>'name',
            ],
        ],
    ],
];
