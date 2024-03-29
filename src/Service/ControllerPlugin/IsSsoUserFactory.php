<?php declare(strict_types=1);

namespace SingleSignOn\Service\ControllerPlugin;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\Mvc\Controller\Plugin\IsSsoUser;

class IsSsoUserFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        return new IsSsoUser(
            $services->get('Omeka\EntityManager')
        );
    }
}
