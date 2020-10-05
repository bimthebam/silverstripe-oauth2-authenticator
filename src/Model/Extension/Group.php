<?php

namespace BimTheBam\OAuth2Authenticator\Model\Extension;

use BimTheBam\OAuth2Authenticator\Model\OAuth2\GroupMapping;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;

/**
 * Class Group
 * @package BimTheBam\OAuth2Authenticator\Model\Extension
 * @method ManyManyList|GroupMapping[] OAuth2ProviderGroupMappings()
 */
class Group extends DataExtension
{
    /**
     * @var string[]
     */
    private static $belongs_many_many = [
        'OAuth2ProviderGroupMappings' => GroupMapping::class,
    ];

    /**
     * @param array $labels
     */
    public function updateFieldLabels(&$labels)
    {
        parent::updateFieldLabels($labels);
        $labels['OAuth2ProviderGroupMappings'] = _t(
            __CLASS__ . '.OAUTH2_PROVIDER_GROUP_MAPPINGS',
            'OAuth2 provider group mappings'
        );
    }
}
