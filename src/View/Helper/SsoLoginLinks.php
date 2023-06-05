<?php declare(strict_types=1);

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
     * - template (string): Use another template.
     * Other options are passed to template.
     */
    public function __invoke(array $options = []): ?string
    {
        $view = $this->getView();

        $options['idps'] = $view->setting('singlesignon_idps') ?: [];

        $options += [
            'heading' => $view->translate('Login with your identity provider'), // @translate
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
