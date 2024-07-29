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
                'name' => 'o:block[__blockIndex__][o:data][internal]',
                'type' => Element\Checkbox::class,
                'options' => [
                    'label' => 'Include default login link', // @translate
                ],
                'attributes' => [
                    'id' => 'sso-login-links-internal',
                ],
            ])
            ->add([
                'name' => 'o:block[__blockIndex__][o:data][selector]',
                'type' => Element\Radio::class,
                'options' => [
                    'label' => 'Input element', // @translate
                    'value_options' => [
                        '' => 'Automatic', // @translate
                        'link' => 'Links', // @translate
                        'button' => 'Buttons', // @translate
                        // A space is appended to simplify translation.
                        'select' => 'Select ', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'sso-login-links-selector',
                ],
            ])
        ;
    }
}
