<?php declare(strict_types=1);

namespace SingleSignOn\Service\ControllerPlugin;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SingleSignOn\Http\HttpClientFix;
use SingleSignOn\Mvc\Controller\Plugin\SsoFederationMetadata;

class SsoFederationMetadataFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        /** @var \Laminas\Http\Client $httpClient */
        if (!function_exists('gzdecode')) {
            $httpClient = $services->get('Omeka\HttpClient');
        } else {
            $config = $services->get('Config');
            $httpClientOptions = $config['http_client'] ?? [];
            $httpClient = new HttpClientFix(null, $httpClientOptions);
        }

        return new SsoFederationMetadata(
            $httpClient
        );
    }
}
