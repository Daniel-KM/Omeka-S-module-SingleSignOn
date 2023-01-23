<?php declare(strict_types=1);

namespace SingleSignOn\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;
use Omeka\Form\Element as OmekaElement;

class ConfigForm extends Form
{
    public function init(): void
    {
        $this
            ->setAttribute('id', 'singlesignon')
            ->add([
                'name' => 'singlesignon_idp_entity_id',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'IdP Entity Id', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_entity_id',
                    'required' => true,
                ],
            ])
            ->add([
                'name' => 'singlesignon_idp_sso_url',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'Url of the IdP single sign-on (SSO) service endpoint', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_sso_url',
                    'required' => true,
                ],
            ])
            ->add([
                'name' => 'singlesignon_idp_slo_url',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Url of the IdP single log out (SLO) service endpoint', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_slo_url',
                ],
            ])
            ->add([
                'name' => 'singlesignon_idp_x509_certificate',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Public X.509 certificate of the IdP', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_x509_certificate',
                    'required' => true,
                ],
            ])
            ->add([
                'name' => 'singlesignon_attributes_map',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Attribute map between IdP and Omeka', // @translate
                    'info' => 'List of IdP and Omeka keys separated by "=". Required Omeka keys are "email" and "name".', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'singlesignon_attributes_map',
                    'required' => true,
                    'placeholder' => 'mail = email
fullname = name',
                ],
            ]);
    }
}
