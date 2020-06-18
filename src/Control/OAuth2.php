<?php

namespace BimTheBam\OAuth2Authenticator\Control;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use GuzzleHttp\Client;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;

/**
 * Class OAuth2
 * @package BimTheBam\OAuth2Authenticator\Control
 */
class OAuth2 extends Controller
{
    /**
     * @var string
     */
    private static $url_segment = 'oauth2';

    /**
     * @var string[]
     */
    private static $allowed_actions = [
        'initAuthFlow',
        'callback',
    ];

    /**
     * @param Provider $provider
     * @return bool|string
     */
    public static function get_callback_url_for_provider(Provider $provider)
    {
        return Director::absoluteURL(
            Controller::join_links(
                static::singleton()->Link('callback'),
                $provider->ID
            )
        );
    }

    /**
     * @param HTTPRequest $request
     * @return \SilverStripe\Control\HTTPResponse|null
     */
    public function index(HTTPRequest $request)
    {
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * @param HTTPRequest $request
     * @return \SilverStripe\Control\HTTPResponse|null
     * @throws \SilverStripe\Control\HTTPResponse_Exception
     */
    public function initAuthFlow(HTTPRequest $request)
    {
        /** @var Provider $provider */
        if (empty($providerID = $request->param('ID'))) {
            $this->httpError(400, 'No provider id given');
        }

        /** @var Provider $provider */
        if (!($provider = Provider::get()->filter(['Active' => true])->byID($providerID))) {
            $this->httpError(404, 'Provider not found');
        }

        $query = [
            'response_type' => 'code',
            'client_id' => $provider->ClientID,
            'redirect_uri' => static::get_callback_url_for_provider($provider),
        ];

        if (!empty($provider->Scopes)) {
            $query['scope'] = $provider->Scopes;
        }

        $url = $provider->AuthorizationEndpoint . '?' . http_build_query($query);

        return $this->redirect($url);
    }

    public function callback(HTTPRequest $request)
    {
        if (empty($providerID = $request->param('ID'))) {
            $this->httpError(400, 'No provider id given');
        }

        if (empty($code = $request->requestVar('code'))) {
            $this->httpError(400, 'No code given');
        }

        /** @var Provider $provider */
        if (!($provider = Provider::get()->filter(['Active' => true])->byID($providerID))) {
            $this->httpError(404, 'Provider not found');
        }

        $postData = [
            'code' => $code,
            'grant_type' => 'authorization_code',
            'client_id' => $provider->ClientID,
            'client_secret' => $provider->ClientSecret,
            'redirect_uri' => static::get_callback_url_for_provider($provider),
        ];

        if (!empty($provider->Scopes)) {
            $postData['scope'] = $provider->Scopes;
        }

        $client = new Client();

        $response = null;

        try {
            $response = $client->post(
                $provider->TokenEndpoint,
                [
                    'form_params' => $postData,
                ]
            );
        } catch (\Exception $e) {
            $this->httpError(500, $e->getMessage());
        }

        var_dump((string)$response->getBody());
    }
}
