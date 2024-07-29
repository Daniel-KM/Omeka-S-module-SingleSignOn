<?php declare(strict_types=1);

namespace SingleSignOn\Service\Form;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\Form\ConfigForm;

class ConfigFormFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        $federations = $services->get('Config')['singlesignon']['federations'];

        $form = new ConfigForm(null, [
            'federations' => array_combine(array_keys($federations), array_keys($federations)),
        ]);
        return $form
            ->setTranslator($services->get('MvcTranslator'))
        ;
    }
}
