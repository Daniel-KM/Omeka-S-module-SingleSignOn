<?php declare(strict_types=1);

namespace SingleSignOn\Form;

use Laminas\Form\Element;
use Laminas\Form\Form;
use OneLogin\Saml2\Constants as SamlConstants;

class ConfigForm extends Form
{
    /**
     * Technical note
     * For creating collections of fieldset with a different name for each
     * element, use __construct() and not init(). But not enough, the main name
     * is missing (only index is added), so currently managed in Module.
     * @see https://docs.laminas.dev/laminas-form/v3/collections
     */
    public function init(): void
    {
        $this
            ->setAttribute('id', 'singlesignon')
            ->setAttribute('name', 'singlesignon')

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
                        'update_user_name' => 'Update user name', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_services',
                    // Default value for collection template.
                    'value' => ['sso'],
                ],
            ])

            ->add([
                'name' => 'singlesignon_append_links_to_login_view',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Append idp links to login view', // @translate
                    'info' => 'The list of idps can be displayed on any page via the theme block and helper.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_append_links_to_login_view',
                ],
            ])

            // Service Provider (SP).

            ->add([
                'name' => 'singlesignon_sp_metadata_content_type',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Metadata content type', // @translate
                    'info' => 'Some IdP require response header content type to be simple xml.', // @translate
                    'value_options' => [
                        'saml' => 'application/samlmetadata+xml', // @translate
                        'xml' => 'application/xml', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_metadata_disposition',
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_metadata_disposition',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Metadata content disposition', // @translate
                    'info' => 'Some IdP require metadata to be downloadable, not inline.', // @translate
                    'value_options' => [
                        'inline' => 'Inline (display in browser)', // @translate
                        'attachment' => 'Attachment (download in browser)', // @translate
                        'undefined' => 'Undefined', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_metadata_disposition',
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_metadata_mode',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Metadata mode', // @translate
                    'info' => 'Some IdP don’t manage xml prefixes in metadata, so they may be removed.', // @translate
                    'value_options' => [
                        'standard' => 'Standard', // @translate
                        'basic' => 'Basic (xml metadata without prefixes)', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_metadata_mode',
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_name_id_format',
                'type' => Element\Select::class,
                'options' => [
                    'label' => 'SP name id format', // @translate
                    'info' => 'Value to set in xml element `<md:NameIDFormat>`. Let empty to use the default value (persistent).', // @translate
                    'value_options' => [
                        SamlConstants::NAMEID_PERSISTENT => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                        SamlConstants::NAMEID_TRANSIENT => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
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
                    'class' => 'chosen-select',
                    'data-placeholder' => 'Select name id format if needed', // @translate
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_cert_path',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Path for SP certificates (outside of webserver or protected)', // @translate
                    'info' => 'Some idp require certificates. If needed, set the path to it. It should contains a directory "certs/" with at least "sp.crt" and "sp.key". It must be protected, for example with a .htaccess. Take care to renew them when needed.', // @translate
                    'documentation' => 'https://github.com/SAML-Toolkits/php-saml/tree/master/certs',
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_cert_path',
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_x509_certificate',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'SP public certificate (x509)', // @translate
                    'info' => 'Some idp require certificates. If needed and if you cannot use a path, paste public certificate here. Take care to renew them when needed.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_x509_certificate',
                    'rows' => 5,
                ],
            ])

            ->add([
                'name' => 'singlesignon_sp_x509_private_key',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'SP private key (x509)', // @translate
                    'info' => 'Some idp require certificates. If needed and if you cannot use a path, paste private key here. Take care to renew them when needed.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_x509_private_key',
                    'rows' => 5,
                ],
            ])

            // Identity Provider (IdP).

            ->add([
                'type' => Element\Collection::class,
                'name' => 'singlesignon_idps',
                'options' => [
                    'label' => 'Identity providers (IdP)', // @translate
                    'count' => 1,
                    'allow_add' => true,
                    'allow_remove' => true,
                    'should_create_template' => true,
                    // TODO Not working, so managed currently in Module and js (but it seems to be the normal way).
                    'template_placeholder' => '__index__',
                    'create_new_objects' => true,
                    'target_element' => [
                        'type' => IdpFieldset::class,
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_idps',
                ],
            ])
        ;

        $this->getInputFilter()
            ->add([
                'name' => 'singlesignon_services',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_append_links_to_login_view',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_metadata_content_type',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_metadata_disposition',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_metadata_mode',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_sp_name_id_format',
                'required' => false,
            ])
        ;
    }
}
