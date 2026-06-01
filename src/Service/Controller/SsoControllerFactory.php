<?php declare(strict_types=1);

namespace SingleSignOn\Service\Controller;

use Laminas\ServiceManager\Factory\FactoryInterface;
use Psr\Container\ContainerInterface;
use SingleSignOn\Controller\SsoController;
use SingleSignOn\Http\HttpClientFix;

class SsoControllerFactory implements FactoryInterface
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

        return new SsoController(
            $services->get('Omeka\Acl'),
            $services->get('Omeka\AuthenticationService'),
            $services->get('Omeka\EntityManager'),
            $httpClient
        );
    }
}
