<?php

namespace BimTheBam\OAuth2Authenticator\Control;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use Firebase\JWT\JWT;
use Flow\JSONPath\JSONPath;
use GuzzleHttp\Client;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Dev\Debug;
use SilverStripe\Security\Member;
use SilverStripe\Security\RandomGenerator;
use SilverStripe\Security\Security;

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
     * @var int
     */
    private static $state_ttl = 120;

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
     * @param Provider $provider
     * @param bool $test
     * @return bool|string
     */
    public static function get_init_auth_flow_url(Provider $provider, bool $test = false)
    {
        $link = Controller::join_links(
            static::singleton()->link('initAuthFlow'),
            $provider->ID
        );

        if ($test) {
            $link = Controller::join_links($link, '?test=1');
        }

        return Director::absoluteURL($link);
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

        $stateKey = (new RandomGenerator())->randomToken('sha512');

        $request->getSession()->set(
            __CLASS__ . '_' . $providerID . '_state_key',
            $stateKey
        );

        $state = [
            'iss' => Director::absoluteBaseURL(),
            'exp' => (time() + static::config()->get('state_ttl')),
            'test' => false,
        ];
        
        if ((int)$request->requestVar('test') === 1) {
            $state['test'] = true;
        }

        $state = JWT::encode($state, $stateKey, 'HS256');

        $query['state'] = $state;

        $url = $provider->AuthorizationEndpoint . '?' . http_build_query($query);

        return $this->redirect($url);
    }

    /**
     * @param HTTPRequest $request
     * @throws \SilverStripe\Control\HTTPResponse_Exception
     */
    public function callback(HTTPRequest $request)
    {
        if (empty($providerID = $request->param('ID'))) {
            $this->httpError(400, 'No provider id given');
        }

        if (empty($code = $request->requestVar('code'))) {
            $this->httpError(400, 'No code given');
        }

        if (empty($state = $request->requestVar('state'))) {
            $this->httpError(400, 'State parameter missing');
        }

        try {
            $state = JWT::decode(
                $state,
                $request->getSession()->get(__CLASS__ . '_' . $providerID . '_state_key'),
                ['HS256']
            );
        } catch (\Exception $e) {
            $this->httpError(400, $e->getMessage());
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

        if (($body = \json_decode($response->getBody())) === null) {
            $this->httpError(500, 'Invalid json response');
        }

        if (!isset($body->access_token) || empty($accessToken = $body->access_token)) {
            $this->httpError(400, 'No access token given');
        }

        if ($state->test) {
            Debug::show([
                'access_token' => $accessToken
            ]);
        }

        $userInfoResponse = null;

        try {
            $userInfoResponse = $client->get(
                $provider->UserInfoEndpoint,
                [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $accessToken,
                    ]
                ]
            );
        } catch (\Exception $e) {
            $this->httpError(500, $e->getMessage());
        }

        if (($body = \json_decode($userInfoResponse->getBody())) === null) {
            $this->httpError(500, 'Invalid json response');
        }

        $body = new JSONPath($body);

        if (
            !count($email = $body->find($provider->UserInfoEmailPath))
            || ($email = $email->first()) === null
        ) {
            $this->httpError(500, 'Email not found at path: ' . $provider->UserInfoEmailPath);
        }

        if (
            !count($firstName = $body->find($provider->UserInfoFirstNamePath))
            || ($firstName = $firstName->first()) === null
        ) {
            $this->httpError(500, 'First name not found at path: ' . $provider->UserInfoFirstNamePath);
        }

        if (
            !count($surname = $body->find($provider->UserInfoSurnamePath))
            || ($surname = $surname->first()) === null
        ) {
            $this->httpError(500, 'Surname not found at path: ' . $provider->UserInfoSurnamePath);
        }

        if ($state->test) {
            Debug::show([
                'user_info' => [
                    'email' => $email,
                    'first_name' => $firstName,
                    'surname' => $surname,
                ]
            ]);
        }

        /** @var Member $member */
        if (!($member = Member::get()->find('Email', $email))) {
            $member = Member::create();

            if ($state->test) {
                Debug::show('Creating new member');
            } else {
                $member->update([
                    'Email' => $email,
                    'FirstName' => $firstName,
                    'Surname' => $surname,
                ]);

                try {
                    $member->write();
                } catch (\Exception $e) {
                    $this->httpError(500, $e->getMessage());
                }
            }

            if (
                ($defaultGroup = $provider->NewMembersDefaultGroup())
                && $defaultGroup->exists()
                && !$member->inGroup($defaultGroup, true)
            ) {
                if ($state->test) {
                    Debug::show('Adding member to group "' . $defaultGroup->Title . '"');
                } else {
                    try {
                        $defaultGroup->Members()->add($member);
                    } catch (\Exception $e) {
                        $this->httpError(500, $e->getMessage());
                    }
                }
            }
        }

        Security::setCurrentUser($member);

        return $this->redirect(Director::absoluteBaseURL());
    }
}
