<?php declare(strict_types=1);

namespace SingleSignOn\Form;

use Laminas\Form\Element;
use Laminas\Form\Fieldset;
use Laminas\InputFilter\InputFilterProviderInterface;
use Omeka\Form\Element as OmekaElement;

class IdpFieldset extends Fieldset implements InputFilterProviderInterface
{
    public function init(): void
    {
        $this
            ->setAttribute('id', 'idp')
            ->setAttribute('class', 'singlesignon-idp idp')
            ->setName('idp')
            ->add([
                'name' => 'idp_entity_id',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'IdP Entity Id', // @translate
                    'info' => 'Full url set in attribute `entityID` of xml element `<md:EntityDescriptor>`, for example "https://idp.example.org". For some IdP, the scheme must not be set, so try "idp.example.org" too.', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_entity_id',
                    'required' => true,
                ],
            ])
            ->add([
                'name' => 'idp_sso_url',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'Url of the IdP single sign-on (SSO) service endpoint', // @translate
                    'info' => 'Full url set in attribute `Location` of xml element `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SSO".', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_sso_url',
                ],
            ])
            ->add([
                'name' => 'idp_slo_url',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'Url of the IdP single log out (SLO) service endpoint', // @translate
                    'info' => 'Full url set in attribute `Location` of xml element `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SLO".', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_slo_url',
                ],
            ])
            ->add([
                'name' => 'idp_x509_certificate',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Public X.509 certificate of the IdP', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_x509_certificate',
                    'required' => true,
                    'rows' => 5,
                ],
            ])
            ->add([
                'name' => 'idp_attributes_map',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Optional attributes map between IdP and Omeka', // @translate
                    'info' => 'List of IdP and Omeka keys separated by "=". IdP keys can be canonical or friendly ones. Managed Omeka keys are "email", "name" and "role".', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'idp_attributes_map',
                    'rows' => 5,
                    'placeholder' => 'mail = email
displayName = name
role = role',
                ],
            ])
        ;
    }

    /**
     * This method is required when a fieldset is used as a collection, else the
     * data are not filtered and not returned with getData().
     *
     * {@inheritDoc}
     * @see \Laminas\InputFilter\InputFilterProviderInterface::getInputFilterSpecification()
     */
    public function getInputFilterSpecification()
    {
        $spec = [
            'idp_sso_url' => [
                'required' => false,
            ],
            'idp_slo_url' => [
                'required' => false,
            ],
        ];
        return $spec;
    }
}
