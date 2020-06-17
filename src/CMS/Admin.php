<?php

namespace BimTheBam\OAuth2Authenticator\CMS;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use SilverStripe\Admin\ModelAdmin;

class Admin extends ModelAdmin
{
    private static $url_segment = 'oauth2';

    private static $menu_title = 'OAuth2';

    private static $menu_icon_class = 'font-icon-external-link';

    private static $managed_models = [
        Provider::class,
    ];

    public $showImportForm = false;
}
