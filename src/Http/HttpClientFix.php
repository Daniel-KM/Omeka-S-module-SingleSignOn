<?php declare(strict_types=1);

namespace SingleSignOn\Http;

use Laminas\Http\Client as HttpClient;
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
}
