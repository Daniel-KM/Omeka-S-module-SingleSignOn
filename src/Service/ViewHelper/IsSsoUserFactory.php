<?php declare(strict_types=1);

namespace SingleSignOn\Service\ViewHelper;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\View\Helper\IsSsoUser;

class IsSsoUserFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        return new IsSsoUser(
            $services->get('ControllerPluginManager')->get('isSsoUser')
        );
    }
}
