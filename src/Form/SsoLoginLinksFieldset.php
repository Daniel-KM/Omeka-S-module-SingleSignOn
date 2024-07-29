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
        ;
    }
}
