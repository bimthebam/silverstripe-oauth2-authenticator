<?php

namespace BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator;

use BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator;
use SilverStripe\Control\Controller;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;

/**
 * Class LoginHandler
 * @package BimTheBam\OAuth2Authenticator\Security\MemberAuthenticator
 */
class LoginHandler extends RequestHandler
{
    private static array $url_handlers = [
        '' => 'login',
    ];

    private static array $allowed_actions = [
        'login',
    ];

    public function __construct(protected string $link, protected MemberAuthenticator $authenticator)
    {
        parent::__construct();
    }

    public function Link($action = null): string
    {
        $link = Controller::join_links($this->link, $action);

        $this->extend('updateLink', $link, $action);

        return $link;
    }

    public function login(): array
    {
        return [
            'Form' => $this->loginForm(),
        ];
    }

    protected function loginForm(): LoginForm
    {
        return LoginForm::create(
            $this,
            $this->authenticator::class,
            FieldList::create(),
        );
    }
}
