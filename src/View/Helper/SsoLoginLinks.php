<?php declare(strict_types=1);

namespace SingleSignOn\View\Helper;

use Laminas\View\Helper\AbstractHelper;

class SsoLoginLinksAbstractHelper
{
    /**
     * The default partial view script.
     */
    const PARTIAL_NAME = 'common/single-sign-on-login-links';

    /**
     * Get the links to the idp to be able to log.
     */
    public function __invoke(array $options = []): ?string
    {
        $view = $this->getView();

        $options['idps'] = $view->setting('singlesignon_idps') ?: [];

        $options += [
            'internal' => false,
            'template' => self::PARTIAL_NAME,
        ];

        $template = $options['template'] ?: self::PARTIAL_NAME;
        unset($options['template']);

        return $template !== self::PARTIAL_NAME && $view->resolver($template)
            ? $view->partial($template, $options)
            : $view->partial(self::PARTIAL_NAME, $options);
     }
}
