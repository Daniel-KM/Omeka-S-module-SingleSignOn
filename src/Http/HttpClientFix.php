<?php declare(strict_types=1);

namespace SingleSignOn\Http;

use Laminas\Http\Client as HttpClient;
use Laminas\Http\Client\Adapter\Curl;
use Laminas\Http\Client\Adapter\Socket;
use Laminas\Http\Request;

/**
 * Fix laminas uncompressing data with gzdecode() instead of gzinflate().
 *
 * When the http response is gzipped, the uncompression process should use
 * gzdecode(), that manages more encoding subtilities in headers than
 * gzinflate().
 *
 * Only useful when gzdecode() is available, that is the normal case.
 *
 * @todo Remove when the module will require Omeka S 4.3.
 *
 * @see \Laminas\Http\Response::decodeGzip()
 * @see https://github.com/laminas/laminas-http/pull/109
 */
class HttpClientFix extends HttpClient
{
    public function send(?Request $request = null)
    {
        $response = parent::send($request);

        $responseFix = new HttpResponseFix();
        // Useless for http response and normally empty. See HttpClient::send().
        /*
        foreach ($response->getMetadata() as $key => $value) {
            $responseFix->setMetadata($key, $value);
        }
        */
        $responseFix
            ->setHeaders($response->getHeaders())
            ->setVersion($response->getVersion())
            ->setStatusCode($response->getStatusCode())
            ->setReasonPhrase($response->getReasonPhrase())
            ->setContent($response->getContent());

        $this->response = $responseFix;
        return $responseFix;
    }

    /**
     * Build an HttpClientFix from $config['http_client'], applying the same
     * adapter autodetection and HTTP/2 negotiation as the core HttpClient
     * factory. Used by SingleSignOn factories that need the gzdecode fix while
     * still respecting the configured adapter (which may be null when EasyAdmin
     * is active).
     */
    public static function fromConfig(array $httpClientOptions): self
    {
        if (empty($httpClientOptions['adapter'])) {
            $httpClientOptions['adapter'] = extension_loaded('curl')
                ? Curl::class
                : Socket::class;
        }

        $curlOptions = $httpClientOptions['curloptions'] ?? [];
        unset($httpClientOptions['curloptions']);

        $client = new self(null, $httpClientOptions);

        if ($httpClientOptions['adapter'] === Curl::class
            && defined('CURL_HTTP_VERSION_2TLS')
            && !array_key_exists(CURLOPT_HTTP_VERSION, $curlOptions)
        ) {
            $curlOptions[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_2TLS;
        }
        if ($curlOptions) {
            $adapter = $client->getAdapter();
            if ($adapter instanceof Curl) {
                $adapter->setOptions(['curloptions' => $curlOptions]);
            }
        }

        return $client;
    }
}
