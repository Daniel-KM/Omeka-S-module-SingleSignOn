<?php declare(strict_types=1);

namespace SingleSignOn\Service\ControllerPlugin;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata;

class SsoFederationMetadataFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        return new SsoFederationMetadata(
            $services->get('Omeka\HttpClient')
        );
    }
}
