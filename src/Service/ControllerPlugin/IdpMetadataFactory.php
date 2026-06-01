<?php declare(strict_types=1);

namespace SingleSignOn\Service\ControllerPlugin;

use Laminas\ServiceManager\Factory\FactoryInterface;
use Psr\Container\ContainerInterface;
use SingleSignOn\Http\HttpClientFix;
use SingleSignOn\Mvc\Controller\Plugin\IdpMetadata;

class IdpMetadataFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        /** @var \Laminas\Http\Client $httpClient */
        if (!function_exists('gzdecode')) {
            $httpClient = $services->get('Omeka\HttpClient');
        } else {
            $config = $services->get('Config');
            $httpClient = HttpClientFix::fromConfig($config['http_client'] ?? []);
        }

        return new IdpMetadata(
            $httpClient
        );
    }
}
