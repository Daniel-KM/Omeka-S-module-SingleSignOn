<?php declare(strict_types=1);

namespace SingleSignOn\Form;

use Laminas\Form\Element;
use Laminas\Form\Fieldset;

class SsoLoginLinksFieldset extends Fieldset
{
    public function init(): void
    {
        $this
            ->add([
                'name' => 'o:block[__blockIndex__][o:data][heading]',
                'type' => Element\Text::class,
                'options' => [
                    'label' => 'Block title', // @translate
                ],
                'attributes' => [
                    'id' => 'sso-login-links-heading',
                ],
            ])
            ->add([
                'name' => 'o:block[__blockIndex__][o:data][internal]',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Include default login link', // @translate
                ],
                'attributes' => [
                    'id' => 'sso-login-links-internal',
                ],
            ])
        ;

        if (class_exists('BlockPlus\Form\Element\TemplateSelect')) {
            $this
                ->add([
                    'name' => 'template',
                    'type' => 'BlockPlus\Form\Element\TemplateSelect',
                    'options' => [
                        'label' => 'Template to display', // @translate
                        'info' => 'Templates are in folder "common/block-layout" of the theme and should start with "sso-login-links".', // @translate
                        'template' => 'common/block-layout/sso-login-links',
                    ],
                    'attributes' => [
                        'id' => 'sso-login-links-template',
                        'class' => 'chosen-select',
                    ],
                ]);
        }
    }
}
