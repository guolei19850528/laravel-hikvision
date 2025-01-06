<?php
/**
 * 作者:郭磊
 * 邮箱:174000902@qq.com
 * 电话:15210720528
 * Git:https://github.com/guolei19850528/laravel-hikvision
 */

namespace Guolei19850528\Laravel\Hikvision;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

/**
 * @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
 */
class Isc
{
    /**
     * @var string
     */
    protected string $host = '';

    /**
     * @var string
     */
    protected string $ak = '';

    /**
     * @var string
     */
    protected string $sk = '';

    public function getHost(): string
    {
        if (\str($this->host)->endsWith('/')) {
            return \str($this->host)->substr(0, -1)->toString();
        }
        return $this->host;
    }

    public function setHost(string $host): Isc
    {
        $this->host = $host;
        return $this;
    }

    public function getAk(): string
    {
        return $this->ak;
    }

    public function setAk(string $ak): Isc
    {
        $this->ak = $ak;
        return $this;
    }

    public function getSk(): string
    {
        return $this->sk;
    }

    public function setSk(string $sk): Isc
    {
        $this->sk = $sk;
        return $this;
    }

    /**
     * @param string $host
     * @param string $ak
     * @param string $sk
     */
    public function __construct(string $host = '', string $ak = '', string $sk = '')
    {
        $this->setHost($host);
        $this->setAk($ak);
        $this->setSk($sk);
    }

    public function headers(
        string           $url = '',
        string           $method = 'POST',
        array|Collection $headers = []
    ): array|Collection
    {
        $headers = \collect($headers);
        $headers->put('accept', '*/*');
        $headers->put('content-type', 'application/json');
        $headers->put('x-ca-signature-headers', 'x-ca-key,x-ca-nonce,x-ca-timestamp');
        $headers->put('x-ca-key', $this->getAk());
        $headers->put('x-ca-nonce', Str::uuid()->toString());
        $headers->put('x-ca-timestamp', \now()->timestamp * 1000);
        $strings = join("\n", [
                $method,
                \data_get($headers, 'accept', ''),
                \data_get($headers, 'content-type', ''),
                sprintf('%s:%s', 'x-ca-key', \data_get($headers, 'x-ca-key', '')),
                sprintf('%s:%s', 'x-ca-nonce', \data_get($headers, 'x-ca-nonce', '')),
                sprintf('%s:%s', 'x-ca-timestamp', \data_get($headers, 'x-ca-timestamp', '')),
                $url,
            ]
        );
        $signature = base64_encode(hash_hmac('sha256', $strings, $this->getSk(), true));
        $headers->put('x-ca-signature', $signature);
        return $headers->toArray();
    }

    /**
     * 带签名的请求
     * @param string|null $method
     * @param string|null $url
     * @param array|Collection|null $urlParameters
     * @param array|Collection|null $data
     * @param array|Collection|null $query
     * @param array|Collection|null $headers
     * @param array|Collection|null $options
     * @param \Closure|null $responseHandler
     * @return mixed
     * @throws \Exception
     */
    public function requestWithSignature(
        string|null           $method = 'GET',
        string|null           $url = '',
        array|Collection|null $urlParameters = [],
        array|Collection|null $data = [],
        array|Collection|null $query = [],
        array|Collection|null $headers = [],
        array|Collection|null $options = [],
        \Closure|null         $responseHandler = null
    ): mixed
    {
        $method = \str($method)->isEmpty() ? 'GET' : $method;
        $data = \collect($data);
        $query = \collect($query);
        $headers = \collect($headers);
        $urlParameters = \collect($urlParameters);
        $options = \collect($options);
        \data_fill($options, RequestOptions::VERIFY, false);
        \data_fill($options, RequestOptions::CONNECT_TIMEOUT, 300);
        \data_fill($options, RequestOptions::TIMEOUT, 300);
        \data_fill($options, RequestOptions::READ_TIMEOUT, 3000);
        \data_fill($options, RequestOptions::JSON, $data->toArray());
        \data_fill($options, RequestOptions::QUERY, $query->toArray());
        $response = Http::baseUrl($this->getHost())
            ->withHeaders($this->headers( $url,$method, $headers->toArray()))
            ->withUrlParameters($urlParameters->toArray())
            ->send($method, $url, $options->toArray());
        if ($responseHandler instanceof \Closure) {
            return \value($responseHandler($response));
        }
        if ($response->ok()) {
            $json = $response->json();
            if (Validator::make($json, ['code' => 'required|integer|size:0'])->messages()->isEmpty()) {
                return \data_get($json, 'data', []);
            }
        }
        return \collect();
    }
}
