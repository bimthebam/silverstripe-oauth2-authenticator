<?php

namespace BimTheBam\OAuth2Authenticator\Security;

use BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator\LoginHandler;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;

/**
 * Class MemberAuthenticator
 * @package BimTheBam\OAuth2Authenticator\Security
 */
class MemberAuthenticator implements Authenticator
{
    /**
     * @return int
     */
    public function supportedServices(): int
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }

    public function getLoginHandler($link): LoginHandler
    {
        return LoginHandler::create($link, $this);
    }

    public function getLogOutHandler($link)
    {
        return LogoutHandler::create();
    }

    public function getChangePasswordHandler($link)
    {
        return null;
    }

    public function getLostPasswordHandler($link)
    {
        return null;
    }

    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        return null;
    }

    public function checkPassword(Member $member, $password, ValidationResult &$result = null)
    {
        return null;
    }
}
