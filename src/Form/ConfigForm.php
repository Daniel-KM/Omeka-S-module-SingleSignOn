<?php declare(strict_types=1);

namespace SingleSignOn\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;
use Omeka\Form\Element as OmekaElement;
use OneLogin\Saml2\Constants as SamlConstants;

class ConfigForm extends Form
{
    public function init(): void
    {
        $this
            ->setAttribute('id', 'singlesignon')

            ->add([
                'name' => 'singlesignon_services',
                'type' => Element\MultiCheckbox::class,
                'options' => [
                    'label' => 'Active services', // @translate
                    'info' => 'Urls for SSO and SLS should be provided if enabled.', // @translate
                    'value_options' => [
                        'sso' => 'Log in (SSO)', // @translate
                        'sls' => 'Log out (SLS)', // @translate
                        'jit' => 'Register (JIT)', // @translate
                        'update' => 'Update user name', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_services',
                ],
            ])

            // Service Provider (SP).

            ->add([
                'name' => 'singlesignon_sp_name_id_format',
                'type' => Element\Select::class,
                'options' => [
                    'label' => 'SP name id format', // @translate
                    'info' => 'Value to set in xml element `<md:NameIDFormat>`. Let empty to use the default value (persistent).', // @translate
                    'value_options' => [
                        SamlConstants::NAMEID_PERSISTENT => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                        SamlConstants::NAMEID_TRANSIENT  => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                        SamlConstants::NAMEID_ENCRYPTED => 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted',
                        SamlConstants::NAMEID_ENTITY => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
                        SamlConstants::NAMEID_KERBEROS => 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
                        SamlConstants::NAMEID_UNSPECIFIED => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                        SamlConstants::NAMEID_EMAIL_ADDRESS => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                        SamlConstants::NAMEID_X509_SUBJECT_NAME => 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
                        SamlConstants::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME => 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
                    ],
                    'empty_option' => '',
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_name_id_format',
                ],
            ])
            ->add([
                'name' => 'singlesignon_sp_metadata_mode',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Metadata mode', // @translate
                    'info' => 'Some IdP don’t manage xml prefixes in metadata, so they may be removed.', // @translate
                    'value_options' => [
                        'basic' => 'Basic (xml metadata without prefixes)', // @translate
                        'standard' => 'Standard', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_metadata_mode',
                ],
            ])

            // Identity Provider (IdP).

            ->add([
                'name' => 'singlesignon_idp_entity_id',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'IdP Entity Id', // @translate
                    'info' => 'Full url set in attribute `entityID` of xml element `<md:EntityDescriptor>`, for example "https://idp.example.org". For some IdP, the scheme must not be set, so try "idp.example.org" too.', // @translate
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
                    'info' => 'Full url set in attribute `Location` of xml element `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SSO".', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_sso_url',
                ],
            ])
            ->add([
                'name' => 'singlesignon_idp_slo_url',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'Url of the IdP single log out (SLO) service endpoint', // @translate
                    'info' => 'Full url set in attribute `Location` of xml element `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SLO".', // @translate
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
                'name' => 'singlesignon_idp_attributes_map',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Optional attributes map between IdP and Omeka', // @translate
                    'info' => 'List of IdP and Omeka keys separated by "=". IdP keys can be canonical or friendly ones. Managed Omeka keys are "email", "name" and "role".', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'singlesignon_idp_attributes_map',
                    'placeholder' => 'mail = email
displayName = name
role = role',
                ],
            ])
        ;

        $this->getInputFilter()
            ->add([
                'name' => 'singlesignon_services',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_name_id_format',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_metadata_mode',
                'required' => false,
            ])
        ;
    }
}
