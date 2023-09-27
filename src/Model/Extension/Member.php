<?php

namespace BimTheBam\OAuth2Authenticator\Model\Extension;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_Base;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\ValidationResult;

/**
 * Class Member
 * @package BimTheBam\OAuth2Authenticator\Model\Extension
 * @mixin \SilverStripe\Security\Member
 * @property \SilverStripe\Security\Member|Member owner
 * @method ManyManyList|Provider[] OAuth2Providers()
 */
class Member extends DataExtension
{
    /**
     * @var string[]
     */
    private static array $belongs_many_many = [
        'OAuth2Providers' => Provider::class,
    ];

    /**
     * @param FieldList $fields
     * @return void
     */
    public function updateCMSFields(FieldList $fields): void
    {
        parent::updateCMSFields($fields);

        if (
            ($oAuth2Providers = $fields->dataFieldByName('OAuth2Providers'))
            && ($oAuth2Providers instanceof GridField)
        ) {
            $config = GridFieldConfig_Base::create()
                ->addComponent(new GridFieldDeleteAction(true));

            $oAuth2Providers->setConfig($config);
        }
    }

    /**
     * @param $labels
     * @return void
     */
    public function updateFieldLabels(&$labels): void
    {
        parent::updateFieldLabels($labels);

        $labels['OAuth2Providers'] = Provider::singleton()->i18n_plural_name();
    }

    public function canLogin(ValidationResult $result)
    {
        if ($this->owner->OAuth2Providers()->count() > 0) {
            $result->addError(
                _t(
                    __CLASS__ . '.CAN_LOGIN_ERROR_OAUTH_LOGIN_ENABLED',
                    'Login not possible. Please use your appropriated OAuth provider for login.'
                )
            );
        }
    }
}
