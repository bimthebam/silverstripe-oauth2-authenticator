<?php

namespace BimTheBam\OAuth2Authenticator\Control\CMS;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use SilverStripe\Admin\ModelAdmin;

/**
 * Class Admin
 * @package BimTheBam\OAuth2Authenticator\Control\CMS
 */
class Admin extends ModelAdmin
{
    /**
     * @var string
     */
    private static $url_segment = 'oauth2';

    /**
     * @var string
     */
    private static $menu_title = 'OAuth2';

    /**
     * @var string
     */
    private static $menu_icon_class = 'font-icon-external-link';

    /**
     * @var string[]
     */
    private static $managed_models = [
        Provider::class,
    ];

    /**
     * @var bool
     */
    public $showImportForm = false;
}
