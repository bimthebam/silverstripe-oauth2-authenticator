<?php

namespace BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use SilverStripe\Forms\FieldList;
use SilverStripe\Security\LoginForm as BaseLoginForm;

/**
 * Class LoginForm
 * @package BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator
 */
class LoginForm extends BaseLoginForm
{
    public function getAuthenticatorName(): string
    {
        return 'OAuth2';
    }

    protected function getFormFields(): FieldList
    {
        foreach (Provider::get()->filter(['Active' => true]) as $provider) {

        }

        return FieldList::create();
    }

    protected function getFormActions(): FieldList
    {
        return FieldList::create();
    }
}
