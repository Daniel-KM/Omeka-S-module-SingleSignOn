<?php

declare(strict_types=1);

namespace SingleSignOn\View\Helper;

use Laminas\View\Helper\AbstractHelper;

class SsoLoginLinks extends AbstractHelper
{
    /**
     * The default partial view script.
     */
    const PARTIAL_NAME = 'common/sso-login-links';

    /**
     * Get the links to the idp to be able to log.
     *
     * @var array $options Managed options:
     * - heading (string): Add a title to the list.
     * - internal (bool): Include internal login link (admin or guest).
     * - selector (string): button (default) or select (default for federation).
     * - template (string): Use another template.
     * Other options are passed to template.
     * @var string $redirect_url is a URL that is returned from the IDP as RelayState for redirecting to specific page after logging in.
     */
    public function __invoke(array $options = [], $redirect_url = null): ?string
    {
        $view = $this->getView();
        $setting = $view->plugin('setting');

        $options['idps'] = $setting('singlesignon_idps') ?: [];

        $selectors = ['link', 'button', 'select'];
        if ($setting('singlesignon_federation')) {
            $selector = in_array($options['selector'] ?? null, $selectors) ? $options['selector'] : 'select';
        } else {
            $selector = in_array($options['selector'] ?? null, $selectors) ? $options['selector'] : 'button';
        }

        $options += [
            'heading' => $view->translate('Login with your identity provider'), // @translate
            'internal' => false,
            'selector' => $selector,
            'template' => self::PARTIAL_NAME,
            'redirect_url' => $redirect_url,
        ];

        $template = $options['template'] ?: self::PARTIAL_NAME;
        unset($options['template']);

        return $template !== self::PARTIAL_NAME && $view->resolver($template)
            ? $view->partial($template, $options)
            : $view->partial(self::PARTIAL_NAME, $options);
    }
}
