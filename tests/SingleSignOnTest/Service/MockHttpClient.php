<?php declare(strict_types=1);

namespace SingleSignOnTest\Service;

use Laminas\Http\Client;
use Laminas\Http\Response;

/**
 * Mock HTTP client that returns stored fixtures instead of making real HTTP requests.
 */
class MockHttpClient extends Client
{
    /**
     * @var string Path to fixtures directory.
     */
    protected $fixturesPath;

    /**
     * @var array Map of URIs to fixture filenames.
     */
    protected $uriMap = [
        'https://idp.example.org/saml2/metadata' => 'idp-metadata.xml',
        'https://federation.example.org/metadata/idps.xml' => 'federation-metadata.xml',
        'https://idp-nons.example.org/saml2/metadata' => 'idp-metadata-no-namespace.xml',
        'https://idp-minimal.example.org/saml2/metadata' => 'idp-metadata-minimal.xml',
        'https://idp-multi.example.org/saml2/metadata' => 'idp-metadata-multi-certs.xml',
        'https://idp-urn.example.org/saml2/metadata' => 'idp-metadata-urn.xml',
        'https://federation-nons.example.org/metadata/idps.xml' => 'federation-metadata-no-namespace.xml',
    ];

    /**
     * @var array Custom responses for specific URIs.
     */
    protected $customResponses = [];

    public function __construct(string $fixturesPath)
    {
        parent::__construct();
        $this->fixturesPath = $fixturesPath;
    }

    /**
     * Add a custom response for a URI.
     */
    public function addResponse(string $uri, string $content, int $statusCode = 200): void
    {
        $this->customResponses[$uri] = [
            'content' => $content,
            'statusCode' => $statusCode,
        ];
    }

    /**
     * Add a fixture mapping.
     */
    public function addFixture(string $uri, string $fixtureFilename): void
    {
        $this->uriMap[$uri] = $fixtureFilename;
    }

    /**
     * Send HTTP request - returns fixture content instead of making real request.
     *
     * @param \Laminas\Http\Request|null $request
     * @return Response
     */
    public function send($request = null)
    {
        $uri = $this->getUri()->toString();

        // Check for custom response first.
        if (isset($this->customResponses[$uri])) {
            return $this->createResponse(
                $this->customResponses[$uri]['content'],
                $this->customResponses[$uri]['statusCode']
            );
        }

        // Check for fixture mapping.
        if (isset($this->uriMap[$uri])) {
            $fixturePath = $this->fixturesPath . '/' . $this->uriMap[$uri];
            if (file_exists($fixturePath)) {
                $content = file_get_contents($fixturePath);
                return $this->createResponse($content, 200);
            }
        }

        // No fixture found - return 404.
        return $this->createResponse('Not Found', 404);
    }

    /**
     * Create a response object.
     */
    protected function createResponse(string $content, int $statusCode): Response
    {
        $response = new Response();
        $response->setStatusCode($statusCode);
        $response->setContent($content);

        if ($statusCode === 200 && strpos($content, '<?xml') === 0) {
            $response->getHeaders()->addHeaderLine('Content-Type', 'application/xml');
        }

        return $response;
    }

    /**
     * Reset the client state.
     *
     * @return $this
     */
    public function reset()
    {
        parent::reset();
        return $this;
    }
}
