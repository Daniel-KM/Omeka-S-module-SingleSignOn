<?php

declare(strict_types=1);

namespace SingleSignOn\Form;

use Common\Form\Element as CommonElement;
use Laminas\Form\Element;
use Laminas\Form\Form;
use Laminas\Mvc\I18n\Translator;
use OneLogin\Saml2\Constants as SamlConstants;

class ConfigForm extends Form
{
    /**
     * @var \Laminas\Mvc\I18n\Translator
     */
    protected $translator;

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

            // TODO Remove admin role from role select.
            ->add([
                'name' => 'singlesignon_role_default',
                'type' => CommonElement\OptionalRoleSelect::class,
                'options' => [
                    'label' => 'Default role for new users when not configured in idp', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_role_default',
                    'required' => false,
                ],
            ]);

        // Check if group module is installed
        if (class_exists(\Group\Form\Element\GroupSelect::class)) {
            $this->add([
                'name' => 'singlesignon_groups_default',
                'type' => \Group\Form\Element\GroupSelect::class,
                'options' => [
                    'label' => 'Groups', // @translate
                    'info' => 'Default Groups given to newly created users using the Group Module', // @translate
                    'chosen' => true,
                ],
                'attributes' => [
                    'id' => 'singlesignon_groups_default',
                    'multiple' => true,
                ],
            ]);
        }

        $this
            ->add([
                'name' => 'singlesignon_append_links_to_login_view',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Append idp links to login view', // @translate
                    'info' => 'The list of idps can be displayed on any page via the theme block and helper or via module Guest.', // @translate
                    'value_options' => [
                        '' => 'No', // @translate
                        'link' => 'Links', // @translate
                        'button' => 'Buttons', // @translate
                        // A space is appended to simplify translation.
                        'select' => 'Select ', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_append_links_to_login_view',
                ],
            ])
            ->add([
                'name' => 'singlesignon_redirect',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Default redirect page after login', // @translate
                    'info' => 'Set "home" for home page (admin or public), "site" for the current site home, "top" for main public page, "me" for guest account, or any path starting with "/", including "/" itself for main home page.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_redirect',
                    'required' => false,
                ],
            ])

            // Service Provider (SP).

            ->add([
                'name' => 'singlesignon_sp_host_name',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Replace host name when SP is behind a proxy', // @translate
                    'info' => 'This option allows to replace the host domain used by Omeka as internal SP server with the host name used in public.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_host_name',
                    'required' => false,
                ],
            ])

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
                    'info' => 'Some idp require certificates. If needed and not set in next fields, set the path to it. It should contains a directory "certs/" with at least "sp.crt" and "sp.key". It must be protected, for example with a .htaccess. Take care to renew them when needed.', // @translate
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
                    'info' => 'Some idp require certificates. If needed and if not set via a path, paste public certificate here. Take care to renew them when needed.', // @translate
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
                    'info' => 'Some idp require certificates. If needed and not set via a path, paste private key here. Take care to renew them when needed.', // @translate
                ],
                'attributes' => [
                    'id' => 'singlesignon_sp_x509_private_key',
                    'rows' => 5,
                ],
            ])

            // Federation

            ->add([
                'name' => 'singlesignon_federation',
                'type' => Element\Select::class,
                'options' => [
                    'label' => 'Federation', // @translate
                    'info' => 'The idps defined manually below will overwrite the federation ones with the same name. To add a federation, append it to the config.', // @ŧranslate
                    'value_options' => $this->getOption('federations') ?: [],
                    'empty_option' => '',
                ],
                'attributes' => [
                    'id' => 'singlesignon_federation',
                    'class' => 'chosen-select',
                    'data-placeholder' => 'Select a federation…', // @translate
                ],
            ])

            // Identity Provider (IdP).

            ->add([
                'type' => Element\Collection::class,
                'name' => 'singlesignon_idps',
                'options' => [
                    'label' => 'Identity providers (IdP)', // @translate
                    'count' => 0,
                    'allow_add' => true,
                    'allow_remove' => true,
                    'should_create_template' => true,
                    'template_placeholder' => '__index__',
                    'create_new_objects' => true,
                    'target_element' => [
                        'type' => IdpFieldset::class,
                    ],
                ],
                'attributes' => [
                    'id' => 'singlesignon_idps',
                    'required' => false,
                    'class' => 'form-fieldset-collection',
                    'data-label-index' => $this->translator->translate('Idp {index}'), // @ŧranslate
                ],
            ])
            ->add([
                'name' => 'plus',
                'type' => Element\Button::class,
                'options' => [
                    'label' => ' ',
                    'label_options' => [
                        'disable_html_escape' => true,
                    ],
                    'label_attributes' => [
                        'class' => 'config-fieldset-action-label',
                    ],
                ],
                'attributes' => [
                    // Don't use o-icon-add.
                    'class' => 'config-fieldset-action config-fieldset-plus fa fa-plus add-value button',
                    'aria-label' => 'Add an idp', // @translate
                ],
            ])
        ;

        $this->getInputFilter()
            ->add([
                'name' => 'singlesignon_services',
                'required' => false,
            ])
            ->add([
                'name' => 'singlesignon_role_default',
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
            ->add([
                'name' => 'singlesignon_federation',
                'required' => false,
            ])
        ;
    }

    public function setTranslator(Translator $translator): self
    {
        $this->translator = $translator;
        return $this;
    }
}
