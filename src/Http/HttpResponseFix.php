<?php declare(strict_types=1);

namespace SingleSignOn\Http;

use Laminas\Http\Exception;
use Laminas\Http\Response;
use Laminas\Stdlib\ErrorHandler;

/**
 * Fix laminas uncompressing data with gzdecode() instead of gzinflate().
 *
 * When the http response is gzipped, the uncompression process should use
 * gzdecode(), that manages more encoding subtilities in headers than
 * gzinflate().
 *
 * @see \Laminas\Http\Response::decodeGzip()
 * @see https://github.com/laminas/laminas-http/pull/109
 */
class HttpResponseFix extends Response
{
    protected function decodeGzip($body)
    {
        if (
            $body === ''
            || ($this->getHeaders()->has('content-length')
                && (int) $this->getHeaders()->get('content-length')->getFieldValue() === 0)
        ) {
            return '';
        }

        ErrorHandler::start();
        $return = gzdecode($body);
        $test   = ErrorHandler::stop();
        if ($test) {
            throw new Exception\RuntimeException(
                'Error occurred during gzip inflation',
                0,
                $test
            );
        }
        return $return;
    }
}
