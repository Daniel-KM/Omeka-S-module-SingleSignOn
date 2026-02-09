<?php declare(strict_types=1);

namespace SingleSignOnTest;

use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use Laminas\Mvc\MvcEvent;
use Laminas\ServiceManager\ServiceLocatorInterface;
use SingleSignOn\Controller\SsoController;

/**
 * Shared test helpers for SingleSignOn module tests.
 */
trait SingleSignOnTestTrait
{
    /**
     * @var ServiceLocatorInterface
     */
    protected $services;

    /**
     * @var bool Whether admin is logged in.
     */
    protected bool $isLoggedIn = false;

    /**
     * Get the service locator.
     */
    protected function getServiceLocator(): ServiceLocatorInterface
    {
        if (isset($this->application) && $this->application !== null) {
            return $this->application->getServiceManager();
        }
        return $this->getApplication()->getServiceManager();
    }

    /**
     * Login as admin user.
     */
    protected function loginAdmin(): void
    {
        $this->isLoggedIn = true;
        $this->ensureLoggedIn();
    }

    /**
     * Ensure admin is logged in on the current application instance.
     */
    protected function ensureLoggedIn(): void
    {
        $services = $this->getServiceLocator();
        $auth = $services->get('Omeka\AuthenticationService');

        if ($auth->hasIdentity()) {
            return;
        }

        $adapter = $auth->getAdapter();
        $adapter->setIdentity('admin@example.com');
        $adapter->setCredential('root');
        $auth->authenticate();
    }

    /**
     * Logout current user.
     */
    protected function logoutUser(): void
    {
        $this->isLoggedIn = false;
        $auth = $this->getServiceLocator()->get('Omeka\AuthenticationService');
        $auth->clearIdentity();
    }

    /**
     * Get the API manager.
     */
    protected function api(): \Omeka\Api\Manager
    {
        if ($this->isLoggedIn) {
            $this->ensureLoggedIn();
        }
        return $this->getServiceLocator()->get('Omeka\ApiManager');
    }

    /**
     * Get the entity manager.
     */
    public function getEntityManager(): \Doctrine\ORM\EntityManager
    {
        return $this->getServiceLocator()->get('Omeka\EntityManager');
    }

    /**
     * Get the path to the fixtures directory.
     */
    protected function getFixturesPath(): string
    {
        return dirname(__DIR__) . '/fixtures';
    }

    /**
     * Get a fixture file content.
     */
    protected function getFixture(string $name): string
    {
        $path = $this->getFixturesPath() . '/' . $name;
        if (!file_exists($path)) {
            throw new \RuntimeException("Fixture not found: $path");
        }
        return file_get_contents($path);
    }

    /**
     * Load a fixture file and parse as XML.
     */
    protected function getFixtureXml(string $name): \SimpleXMLElement
    {
        return new \SimpleXMLElement($this->getFixture($name));
    }

    /**
     * Setup mock HTTP client to return fixtures instead of real requests.
     */
    protected function setupMockHttpClient(): void
    {
        $services = $this->getServiceLocator();
        $fixturesPath = $this->getFixturesPath();

        $mockClient = new Service\MockHttpClient($fixturesPath);

        $services->setAllowOverride(true);
        $services->setService('Omeka\HttpClient', $mockClient);
        $services->setAllowOverride(false);
    }

    /**
     * Get the mock HTTP client (must call setupMockHttpClient first).
     */
    protected function getMockHttpClient(): Service\MockHttpClient
    {
        return $this->getServiceLocator()->get('Omeka\HttpClient');
    }

    /**
     * Create a controller plugin with a proper controller context.
     *
     * Controller plugins (IdpMetadata, SsoFederationMetadata) call
     * `$this->getController()->logger()` which requires a controller with
     * a ControllerPluginManager. This method sets up that context.
     *
     * @param string $pluginClass Fully qualified class name of the plugin.
     * @return AbstractPlugin The plugin with a controller attached.
     */
    protected function createPluginWithController(string $pluginClass): AbstractPlugin
    {
        $services = $this->getServiceLocator();
        $mockClient = $this->getMockHttpClient();

        // Create the plugin with mock HTTP client.
        $plugin = new $pluginClass($mockClient);

        // Create a SsoController with dependencies.
        $controller = new SsoController(
            $services->get('Omeka\Acl'),
            $services->get('Omeka\AuthenticationService'),
            $services->get('Omeka\EntityManager'),
            $mockClient
        );

        // Set the ControllerPluginManager so logger()/messenger() work.
        $pluginManager = $services->get('ControllerPluginManager');
        $controller->setPluginManager($pluginManager);

        // Set up MvcEvent for routing context.
        $event = new MvcEvent();
        $event->setApplication($this->getApplication());
        $event->setRouter($services->get('Router'));
        $controller->setEvent($event);

        // Attach the controller to the plugin.
        $plugin->setController($controller);

        return $plugin;
    }

    /**
     * Set a module setting in the test database.
     */
    protected function setSetting(string $name, $value): void
    {
        $this->ensureLoggedIn();
        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        $settings->set($name, $value);
    }

    /**
     * Get a module setting from the test database.
     */
    protected function getSetting(string $name, $default = null)
    {
        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        return $settings->get($name, $default);
    }

    /**
     * Create an IdP configuration array for testing.
     */
    protected function createTestIdpConfig(array $overrides = []): array
    {
        return array_merge([
            'metadata_update_mode' => 'manual',
            'metadata_use_federation_data' => false,
            'metadata_keep_entity_id' => false,
            'metadata_url' => 'https://idp.example.org/saml2/metadata',
            'entity_id' => 'https://idp.example.org/saml2',
            'entity_name' => 'Example Identity Provider',
            'entity_short_id' => 'idp.example.org',
            'host' => 'idp.example.org',
            'sso_url' => 'https://idp.example.org/saml2/sso',
            'slo_url' => 'https://idp.example.org/saml2/slo',
            'sign_x509_certificates' => [],
            'crypt_x509_certificates' => [],
            'date' => (new \DateTime('now'))->format(\DateTime::ISO8601),
            'attributes_map' => [
                'mail' => 'email',
                'displayName' => 'name',
            ],
            'roles_map' => [],
            'user_settings' => [],
        ], $overrides);
    }
}
