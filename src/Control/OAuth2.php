<?php

namespace BimTheBam\OAuth2Authenticator\Control;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\GroupMapping;
use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Flow\JSONPath\JSONPath;
use Flow\JSONPath\JSONPathException;
use GuzzleHttp\Client;
use Psr\Container\NotFoundExceptionInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\Debug;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\RandomGenerator;
use SilverStripe\Security\Security;
use stdClass;

/**
 * Class OAuth2
 * @package BimTheBam\OAuth2Authenticator\Control
 */
class OAuth2 extends Controller
{
    /**
     * @var string
     */
    private static string $url_segment = 'oauth2';

    /**
     * @var int
     */
    private static int $state_ttl = 120;

    /**
     * @var string[]
     */
    private static array $allowed_actions = [
        'initAuthFlow',
        'callback',
    ];

    /**
     * @param Provider $provider
     * @return string
     */
    public static function get_callback_url_for_provider(Provider $provider): string
    {
        $url = Director::absoluteURL(
            Controller::join_links(
                static::singleton()->Link('callback'),
                $provider->ID
            )
        );

        return $url !== false ? $url : '';
    }

    /**
     * @param Provider $provider
     * @param bool $test
     * @return string
     */
    public static function get_init_auth_flow_url(Provider $provider, bool $test = false): string
    {
        $link = Controller::join_links(
            static::singleton()->link('initAuthFlow'),
            $provider->ID
        );

        $query = [];

        if (
            Controller::has_curr() &&
            ($request = Controller::curr()->getRequest())
            && !empty($backURL = trim($request->requestVar('BackURL') ?? ''))
            && Director::is_site_url($backURL)
        ) {
            $query['BackURL'] = Director::absoluteURL($backURL);
        }

        if ($test) {
            $query['test'] = '1';
        }

        if (!empty($query)) {
            $link = Controller::join_links(
                $link,
                '?' . http_build_query($query)
            );
        }

        return ($url = Director::absoluteURL($link)) !== false ? $url : '';
    }

    /**
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function index(HTTPRequest $request): HTTPResponse
    {
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * @var CacheInterface|null
     */
    protected ?CacheInterface $openIDDiscoveryCache = null;

    /**
     * @return CacheInterface
     */
    protected function getOpenIDDiscoveryCache(): CacheInterface
    {
        if ($this->openIDDiscoveryCache !== null) {
            return $this->openIDDiscoveryCache;
        }

        return $this->openIDDiscoveryCache = Injector::inst()->create(
            CacheInterface::class .
            '.' .
            str_replace('\\', '_', __CLASS__) . '_openid_discovery'
        );
    }

    /**
     * @param Provider $provider
     * @return stdClass|null
     * @throws InvalidArgumentException
     * @throws HTTPResponse_Exception
     */
    protected function getOpenIDConnectConfiguration(Provider $provider): ?stdClass
    {
        if (empty($discoveryURL = $provider->OpenIDDiscoveryEndpoint)) {
            return null;
        }

        if (($body = $this->getOpenIDDiscoveryCache()->get('provider-' . $provider->ID)) !== null) {
            return $body;
        } else {
            try {
                $client = new Client();
                $response = $client->get($discoveryURL);

                if (($body = json_decode($response->getBody())) === null) {
                    $this->httpError(500, 'Empty or invalid response from OpenID connect.');
                }

                $requiredProperties = [
                    'authorization_endpoint',
                    'token_endpoint',
                    'userinfo_endpoint',
                ];

                foreach ($requiredProperties as $property) {
                    if (($body->{$property} ?? null) === null) {
                        $this->httpError(
                            500,
                            'Invalid OpenID connect configuration. Missing "' . $property . '"'
                        );
                    }
                }

                $this->getOpenIDDiscoveryCache()->set('provider-' . $provider->ID, $body);

                return $body;
            } catch (\Throwable $e) {
                $this->httpError(500, $e->getMessage());
            }
        }

        return null;
    }

    /**
     * @param HTTPRequest $request
     * @return HTTPResponse
     * @throws HTTPResponse_Exception
     * @throws InvalidArgumentException
     */
    public function initAuthFlow(HTTPRequest $request): HTTPResponse
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

        if (!empty($backURL = trim($request->requestVar('BackURL') ?? ''))) {
            $state['back_url'] = $backURL;
        }

        $state = JWT::encode($state, $stateKey, 'HS256');

        $query['state'] = $state;

        if (($config = $this->getOpenIDConnectConfiguration($provider)) !== null) {
            $url = $config->authorization_endpoint;
        } else {
            $url = $provider->AuthorizationEndpoint;
        }

        if (strstr($url, '?')) {
            $url = Controller::join_links($url . '&' . http_build_query($query));
        } else {
            $url = Controller::join_links($url . '?' . http_build_query($query));
        }

        return $this->redirect($url);
    }

    /**
     * @param HTTPRequest $request
     * @return HTTPResponse|null
     * @throws HTTPResponse_Exception
     * @throws InvalidArgumentException
     * @throws JSONPathException
     * @throws NotFoundExceptionInterface
     */
    public function callback(HTTPRequest $request): ?HTTPResponse
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
                new Key(
                    $request->getSession()->get(__CLASS__ . '_' . $providerID . '_state_key'),
                    'HS256'
                )
            );
        } catch (\Throwable $e) {
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

        if (($config = $this->getOpenIDConnectConfiguration($provider)) !== null) {
            $url = $config->token_endpoint;
        } else {
            $url = $provider->TokenEndpoint;
        }

        $client = new Client();

        $response = null;

        try {
            $response = $client->post(
                $url,
                [
                    'form_params' => $postData,
                ]
            );
        } catch (\Throwable $e) {
            $this->httpError(500, $e->getMessage());
        }

        if (($tokenBody = \json_decode($response->getBody())) === null) {
            $this->httpError(500, 'Invalid json response');
        }

        if (!isset($tokenBody->access_token) || empty($accessToken = $tokenBody->access_token)) {
            $this->httpError(400, 'No access token given');
        }

        if ($state->test) {
            Debug::show($tokenBody);
        }

        if (($config = $this->getOpenIDConnectConfiguration($provider)) !== null) {
            $url = $config->userinfo_endpoint;
        } else {
            $url = $provider->UserInfoEndpoint;
        }

        $userInfoResponse = null;

        try {
            $userInfoResponse = $client->get(
                $url,
                [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $accessToken,
                    ]
                ]
            );
        } catch (\Throwable $e) {
            $this->httpError(500, $e->getMessage());
        }

        if (($userInfoBody = \json_decode($userInfoResponse->getBody())) === null) {
            $this->httpError(500, 'Invalid json response');
        }

        if ($state->test) {
            Debug::show('User info reponse');
            Debug::show($userInfoBody);
        }

        $body = new JSONPath($userInfoBody);

        if (
            !count($email = $body->find($provider->UserInfoEmailPath))
            || ($email = $email->first()) === null
        ) {
            $this->httpError(500, 'Email not found at path: ' . $provider->UserInfoEmailPath);
        }

        $firstName = null;

        if (!empty($provider->UserInfoFirstNamePath)) {
            if (
                !count($firstName = $body->find($provider->UserInfoFirstNamePath))
                || ($firstName = $firstName->first()) === null
            ) {
                $this->httpError(
                    500,
                    'First name not found at path: ' . $provider->UserInfoFirstNamePath
                );
            }
        }

        $surname = null;

        if (!empty($provider->UserInfoSurnamePath)) {
            if (
                !count($surname = $body->find($provider->UserInfoSurnamePath))
                || ($surname = $surname->first()) === null
            ) {
                $this->httpError(
                    500,
                    'Surname not found at path: ' . $provider->UserInfoSurnamePath
                );
            }
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

        /** @var Member|\BimTheBam\OAuth2Authenticator\Model\Extension\Member $member */
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
                } catch (\Throwable $e) {
                    $this->httpError(500, $e->getMessage());
                }
            }
        }

        $addToGroups = [];

        if (
            ($defaultGroup = $provider->NewMembersDefaultGroup())
            && $defaultGroup->exists()
            && !$member->inGroup($defaultGroup, true)
        ) {
            $addToGroups[$defaultGroup->ID] = $defaultGroup;
        }

        if (
            !empty($groupsInfoEndpoint = $provider->GroupsInfoEndpoint)
            && !empty($groupsInfoIdentifierPath = $provider->GroupsInfoIdentifierPath)
        ) {
            $groupsInfoResponse = null;

            try {
                $groupsInfoResponse = $client->get(
                    $groupsInfoEndpoint,
                    [
                        'headers' => [
                            'Authorization' => 'Bearer ' . $accessToken,
                        ]
                    ]
                );
            } catch (\Throwable $e) {
                $this->httpError(500, $e->getMessage());
            }

            if (($groupsInfoBody = \json_decode($groupsInfoResponse->getBody())) === null) {
                $this->httpError(500, 'Invalid json response');
            }

            if ($state->test) {
                Debug::show('Group(s) info reponse');
                Debug::show($groupsInfoBody);
            }

            $groupsInfoBody = new JSONPath($groupsInfoBody);

            if (count($ids = $groupsInfoBody->find($groupsInfoIdentifierPath))) {
                foreach ($ids as $id) {
                    $groupMappings = GroupMapping::get()->where(["FIND_IN_SET(?, ExternalGroupIDs)" => $id]);

                    /** @var GroupMapping $groupMapping */
                    foreach ($groupMappings as $groupMapping) {
                        foreach ($groupMapping->Groups() as $group) {
                            if (!$group->DirectMembers()->byID($member->ID)) {
                                $addToGroups[$group->ID] = $group;
                            }
                        }
                    }
                }
            }
        }

        if (count($addToGroups)) {
            foreach ($addToGroups as $group) {
                if ($state->test) {
                    Debug::show('Adding member to group "' . $group->Title . '"');
                } else {
                    try {
                        $group->Members()->add($member);
                    } catch (\Throwable $e) {
                        $this->httpError(500, $e->getMessage());
                    }
                }
            }
        }

        if (!$state->test) {
            $member->OAuth2Providers()->add($provider);

            /** @var IdentityStore $identityStore */
            $identityStore = Injector::inst()->get(IdentityStore::class);
            $identityStore->logIn($member, false, $request);

            Security::setCurrentUser($member);

            $this->invokeWithExtensions(
                'onAfterTokenAuthorization',
                $request,
                $provider,
                $state,
                $tokenBody,
                $userInfoBody
            );

            $backURL = !empty($backURL = trim($state->back_url ?? ''))
                ? $backURL
                : Director::absoluteBaseURL();

            return $this->redirect($backURL);
        }

        return null;
    }
}
