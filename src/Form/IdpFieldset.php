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
            ->setAttribute('class', 'form-fieldset-element singlesignon-idp idp')
            ->setName('idp')

            ->add([
                'name' => 'metadata_url',
                'type' => Element\Url::class,
                'options' => [
                    'label' => 'IdP metadata url (allow to get and update settings automatically)', // @translate
                    'info' => 'For Shibboleth, it may be "https://idp.example.org/idp/shibboleth".', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_metadata_url',
                    'required' => false,
                ],
            ])

            // Automatically fillable data (except id when option is set).

            ->add([
                'name' => 'entity_id',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'IdP Entity Id', // @translate
                    'info' => 'Full url set in attribute `entityID` of xml element `<md:EntityDescriptor>`, for example "https://idp.example.org". For some IdP, the scheme must not be set, so try "idp.example.org" too.', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_entity_id',
                    'required' => false,
                ],
            ])

            ->add([
                'name' => 'entity_name',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'IdP name', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_entity_name',
                    'required' => false,
                ],
            ])
            ->add([
                'name' => 'sso_url',
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
                'name' => 'slo_url',
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
                'name' => 'sign_x509_certificate',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Public X.509 certificate of the IdP (signing)', // @translate
                    'info' => 'If not set, it will be fetched from the IdP url, if available.', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_sign_x509_certificate',
                    'rows' => 5,
                ],
            ])
            ->add([
                'name' => 'crypt_x509_certificate',
                'type' => Element\Textarea::class,
                'options' => [
                    'label' => 'Public X.509 certificate of the IdP (encryption)', // @translate
                    'info' => 'If not set, it will be fetched from the IdP url, if available.', // @translate
                ],
                'attributes' => [
                    'id' => 'idp_crypt_x509_certificate',
                    'rows' => 5,
                ],
            ])

            // Specific manual options.

            ->add([
                'name' => 'attributes_map',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Attributes map between IdP and Omeka', // @translate
                    'info' => 'List of IdP and Omeka keys separated by "=". IdP keys can be canonical or friendly ones. Managed Omeka keys are "email", "name" and "role". Other options, like "locale", "userprofile_param", are stored in user settings.', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'idp_attributes_map',
                    'rows' => 5,
                    'placeholder' => <<<'TXT'
                        mail = email
                        displayName = name
                        role = role
                        TXT,
                ],
            ])
            ->add([
                'name' => 'roles_map',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Roles map between IdP and Omeka', // @translate
                    'info' => 'Allows to get a more precise role than the default "researcher" or "guest". List of IdP and Omeka roles separated by "=". For security, admin roles are disabled: update the user manually once created.', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'idp_roles_map',
                    'rows' => 5,
                    'placeholder' => <<<'TXT'
                        scholar = guest
                        librarian = author
                        TXT,
                ],
            ])
            ->add([
                'name' => 'user_settings',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Static user settings for new users', // @translate
                    'as_key_value' => true,
                ],
                'attributes' => [
                    'id' => 'idp_user_settings',
                    'rows' => 5,
                    'placeholder' => <<<'TXT'
                        locale = fr
                        guest_agreed_terms = 1
                        userprofile_key = value
                        TXT,
                ],
            ])

            ->add([
                'name' => 'metadata_update_mode',
                'type' => Element\Select::class,
                'options' => [
                    'label' => 'Update mode', // @translate
                    'label_attributes' => [
                        'style' => 'display: block;',
                    ],
                    'value_options' => [
                        'auto' => 'Automatic (set the url and the id and data will be automatically filled, checked and updated)', // @translate
                        'auto_except_id' => 'Automatic, except entity id (fix possible issue with reverse proxies)', // @translate
                        'manual' => 'Manual (not recommended, because most certificates have a limited lifetime)', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'idp_metadata_update_mode',
                    'required' => false,
                    'value' => 'auto',
                ],
            ])

            ->add([
                'name' => 'minus',
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
                    // Don't use o-icon-delete.
                    'class' => 'config-fieldset-action config-fieldset-minus fa fa-minus remove-value button',
                    'aria-label' => 'Remove this idp', // @translate
                ],
            ])
            ->add([
                'name' => 'up',
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
                    // Don't use o-icon-delete.
                    'class' => 'config-fieldset-action config-fieldset-up fa fa-arrow-up button',
                    'aria-label' => 'Move this idp up', // @translate
                ],
            ])
            ->add([
                'name' => 'down',
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
                    // Don't use o-icon-delete.
                    'class' => 'config-fieldset-action config-fieldset-down fa fa-arrow-down button',
                    'aria-label' => 'Move this idp down', // @translate
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
        return [
            'metadata_url' => [
                'required' => false,
            ],
            'sso_url' => [
                'required' => false,
            ],
            'slo_url' => [
                'required' => false,
            ],
            'metadata_update_mode' => [
                'required' => false,
            ],
        ];
    }
}
