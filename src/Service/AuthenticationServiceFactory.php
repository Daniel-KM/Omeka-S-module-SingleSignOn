<?php declare(strict_types=1);

namespace SingleSignOn\Service;

use Interop\Container\ContainerInterface;
use Laminas\Authentication\Adapter\Callback;
use Laminas\Authentication\AuthenticationService;
use Laminas\Authentication\Storage\NonPersistent;
use Laminas\Authentication\Storage\Session;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Omeka\Authentication\Adapter\KeyAdapter;
use Omeka\Authentication\Adapter\PasswordAdapter;
use Omeka\Authentication\Storage\DoctrineWrapper;

/**
 * Authentication service factory.
 *
 * @see \Omeka\Service\AuthenticationServiceFactory
 */
class AuthenticationServiceFactory implements FactoryInterface
{
    /**
     * Create the authentication service.
     *
     * @return AuthenticationService
     */
    public function __invoke(ContainerInterface $services, $requestedName, array $options = null)
    {
        /** @var \Omeka\Mvc\Status $status */
        $entityManager = $services->get('Omeka\EntityManager');
        $status = $services->get('Omeka\Status');

        // Skip auth retrieval entirely if we're installing or migrating.
        if (!$status->isInstalled() ||
            ($status->needsVersionUpdate() && $status->needsMigration())
        ) {
            $storage = new NonPersistent;
            $adapter = new Callback(fn () => null);
        } else {
            $config = $services->get('Config');
            $userRepository = $entityManager->getRepository('Omeka\Entity\User');
            // Keep old Api check to simplify upgrade/migration.
            if (method_exists($status, 'isKeyauthRequest') && $status->isKeyauthRequest()) {
                // Authenticate using key for requests that require key authentication.
                $keyRepository = $entityManager->getRepository('Omeka\Entity\ApiKey');
                $storage = new DoctrineWrapper(new NonPersistent, $userRepository);
                $adapter = new KeyAdapter($keyRepository, $entityManager);
            } elseif (!method_exists($status, 'isKeyauthRequest') && $status->isApiRequest()) {
                    // Authenticate using key for requests that require key authentication.
                    $keyRepository = $entityManager->getRepository('Omeka\Entity\ApiKey');
                    $storage = new DoctrineWrapper(new NonPersistent, $userRepository);
                    $adapter = new KeyAdapter($keyRepository, $entityManager);
            } elseif ($config['authentication']['forbid_local_login']) {
                // Disallow local login and log out logged users if wanted.
                $storage = $config['authentication']['logout_logged_users']
                    ? new NonPersistent
                    : new DoctrineWrapper(new Session, $userRepository);
                $adapter = new Callback(fn () => null);
            } else {
                // Authenticate using user/password for all other requests.
                $storage = new DoctrineWrapper(new Session, $userRepository);
                $adapter = new PasswordAdapter($userRepository);
            }
        }

        return new AuthenticationService($storage, $adapter);
    }
}
