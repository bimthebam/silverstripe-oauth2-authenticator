<?php

namespace BimTheBam\OAuth2Authenticator\Model\Extension;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\Provider;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_Base;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;

/**
 * Class Member
 * @package BimTheBam\OAuth2Authenticator\Model\Extension
 * @mixin \SilverStripe\Security\Member
 * @property \SilverStripe\Security\Member owner
 * @method ManyManyList|Provider[] OAuth2Providers()
 */
class Member extends DataExtension
{
    /**
     * @var string[]
     */
    private static $belongs_many_many = [
        'OAuth2Providers' => Provider::class,
    ];

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
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
     * @param array $labels
     */
    public function updateFieldLabels(&$labels)
    {
        parent::updateFieldLabels($labels);
        $labels['OAuth2Providers'] = Provider::singleton()->i18n_plural_name();
    }
}
