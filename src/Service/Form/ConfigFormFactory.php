<?php declare(strict_types=1);

namespace SingleSignOn\Service\Form;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\Form\ConfigForm;

class ConfigFormFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        $form = new ConfigForm(null, $options ?? []);
        return $form
            ->setTranslator($services->get('MvcTranslator'))
        ;
    }
}
