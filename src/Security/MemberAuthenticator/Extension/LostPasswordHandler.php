<?php

namespace BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator\Extension;

use SilverStripe\Core\Extension;
use SilverStripe\Security\Member;

/**
 * Class LostPasswordHandler
 * @package BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator\Extension
 */
class LostPasswordHandler extends Extension
{
    /**
     * @param Member|null $member
     * @return bool
     */
    public function forgotPassword(?Member $member): bool
    {
        /** @var Member|\BimTheBam\OAuth2Authenticator\Model\Extension\Member $member */
        return !empty($member)
            && $member->OAuth2Providers()->count() === 0;
    }
}
