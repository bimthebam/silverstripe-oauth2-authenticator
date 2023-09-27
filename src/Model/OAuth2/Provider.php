<?php

namespace BimTheBam\OAuth2Authenticator\Model\OAuth2;

use BimTheBam\OAuth2Authenticator\Control\OAuth2;
use SilverStripe\AssetAdmin\Forms\UploadField;
use SilverStripe\Assets\Image;
use SilverStripe\Core\Environment;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RecordViewer;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\TextareaField;
use SilverStripe\Forms\TreeDropdownField;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBBoolean;
use SilverStripe\ORM\FieldType\DBText;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\ORM\HasManyList;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\View\TemplateGlobalProvider;

/**
 * Class Provider
 * @package BimTheBam\OAuth2Authenticator\Model\OAuth2
 * @property bool Active
 * @property string Title
 * @property string OpenIDDiscoveryEndpoint
 * @property string AuthorizationEndpoint
 * @property string TokenEndpoint
 * @property string UserInfoEndpoint
 * @property string UserInfoEmailPath
 * @property string UserInfoFirstNamePath
 * @property string UserInfoSurnamePath
 * @property string GroupsInfoEndpoint
 * @property string GroupsInfoIdentifierPath
 * @property string ClientID
 * @property string Scopes
 * @property int NewMembersDefaultGroupID
 * @method Group NewMembersDefaultGroup()
 * @property int IconID
 * @method Image Icon()
 * @method HasManyList|GroupMapping[] GroupMappings()
 * @method ManyManyList|Member[] Members()
 * @property string ClientSecretEnvKey
 * @property string ClientSecret
 */
class Provider extends DataObject implements TemplateGlobalProvider
{
    /**
     * @var string
     */
    private static string $table_name = 'OAuth2Provider';

    /**
     * @var string
     */
    private static string $singular_name = 'OAuth2 provider';
    #
    /**
     * @var string
     */
    private static string $plural_name = 'OAuth2 providers';

    /**
     * @var string[]
     */
    private static array $db = [
        'Active' => DBBoolean::class,
        'Title' => DBVarchar::class . '(50)',
        'OpenIDDiscoveryEndpoint' => DBVarchar::class . '(255)',
        'AuthorizationEndpoint' => DBVarchar::class . '(255)',
        'TokenEndpoint' => DBVarchar::class . '(255)',
        'UserInfoEndpoint' => DBVarchar::class . '(255)',
        'UserInfoEmailPath' => DBVarchar::class . '(255)',
        'UserInfoFirstNamePath' => DBVarchar::class . '(255)',
        'UserInfoSurnamePath' => DBVarchar::class . '(255)',
        'GroupsInfoEndpoint' => DBVarchar::class . '(255)',
        'GroupsInfoIdentifierPath' => DBVarchar::class . '(255)',
        'ClientID' => DBText::class,
        'Scopes' => DBVarchar::class . '(255)',
    ];

    /**
     * @var string[]
     */
    private static array $has_one = [
        'NewMembersDefaultGroup' => Group::class,
        'Icon' => Image::class,
    ];

    /**
     * @var string[]
     */
    private static array $has_many = [
        'GroupMappings' => GroupMapping::class,
    ];

    /**
     * @var string[]
     */
    private static array $many_many = [
        'Members' => Member::class,
    ];

    /**
     * @var string[]
     */
    private static array $summary_fields = [
        'Active.Nice',
        'Title',
    ];

    /**
     * @var string[]
     */
    private static array $owns = [
        'Icon',
    ];

    /**
     * @return FieldList
     */
    public function getCMSFields(): FieldList
    {
        $this->beforeUpdateCMSFields(function (FieldList $fields) {
            if ($openIDDiscoveryEndpoint = $fields->dataFieldByName('OpenIDDiscoveryEndpoint')) {
                $openIDDiscoveryEndpoint->setAttribute(
                    'placeholder',
                    _t(
                        __CLASS__ . '.OPEN_ID_DISCOVERY_ENDPOINT_PLACEHOLDER',
                        'https://example.com/.well-known/openid-configuration'
                    )
                );
            }

            if ($authorizationEndpoint = $fields->dataFieldByName('AuthorizationEndpoint')) {
                $authorizationEndpoint->setAttribute(
                    'placeholder',
                    _t(__CLASS__ . '.AUTHORIZATION_ENDPOINT_PLACEHOLDER', 'https://example.com/oauth2/authorize')
                );
            }

            if ($tokenEndpoint = $fields->dataFieldByName('TokenEndpoint')) {
                $tokenEndpoint->setAttribute(
                    'placeholder',
                    _t(__CLASS__ . '.TOKEN_ENDPOINT_PLACEHOLDER', 'https://example.com/oauth2/access_token')
                );
            }

            if ($userInfoEndpoint = $fields->dataFieldByName('UserInfoEndpoint')) {
                $userInfoEndpoint->setAttribute(
                    'placeholder',
                    _t(__CLASS__ . '.USER_INFO_ENDPOINT_PLACEHOLDER', 'https://example.com/api/me')
                );
            }

            if ($groupsInfoEndpoint = $fields->dataFieldByName('GroupsInfoEndpoint')) {
                $groupsInfoEndpoint->setAttribute(
                    'placeholder',
                    _t(__CLASS__ . '.GROUPS_INFO_ENDPOINT_PLACEHOLDER', 'https://example.com/api/me/groups')
                );
            }

            $pathDescriptionPlain = _t(
                __CLASS__ . '.PATH_DESCRIPTION_PLAIN',
                'e.g. $.fieldName' .
                '<br/>' .
                ' (see <a href="https://github.com/FlowCommunications/JSONPath#jsonpath-examples" target="_blank">' .
                'https://github.com/FlowCommunications/JSONPath#jsonpath-examples</a> for examples)'
            );

            $fieldsToDescribe = [
                'UserInfoEmailPath',
                'UserInfoFirstNamePath',
                'UserInfoSurnamePath',
                'GroupsInfoIdentifierPath',
            ];

            foreach ($fieldsToDescribe as $field) {
                if (($field = $fields->dataFieldByName($field))) {
                    $field->setDescription($pathDescriptionPlain)
                        ->setAttribute('placeholder', '$.fieldName');
                }
            }

            if (($clientID = $fields->dataFieldByName('ClientID')) && ($clientID instanceof TextareaField)) {
                $clientID->setRows(1);
            }

            if (
                ($newMembersDefaultGroup = $fields->dataFieldByName('NewMembersDefaultGroup'))
                && !($newMembersDefaultGroup instanceof TreeDropdownField)
            ) {
                $fields->replaceField(
                    'NewMembersDefaultGroup',
                    TreeDropdownField::create(
                        'NewMembersDefaultGroup',
                        $this->fieldLabel('NewMembersDefaultGroup'),
                        Group::get()
                    )
                );
            }

            if (($icon = $fields->dataFieldByName('Icon')) && ($icon instanceof UploadField)) {
                $icon->setFolderName('OAuth2/Provider');
            }

            if ($this->exists()) {
                if (empty($this->ClientSecret)) {
                    $fields->insertAfter(
                        'ClientID',
                        LiteralField::create(
                            'ClientSecretDescription',
                            _t(
                                __CLASS__ . '.CLIENT_SECRET_DESCRIPTION',
                                '<p class="alert alert-danger">' .
                                'The client secret must be stored secretly. ' .
                                'Please add it to your .env file:' .
                                '</p>'
                            )
                        )
                    );

                    $fields->insertAfter(
                        'ClientSecretDescription',
                        ReadonlyField::create(
                            'ClientSecretInstallationHint',
                            $this->fieldLabel('ClientSecret'),
                            'OAUTH2_CLIENT_SECRET_PROVIDER_' . $this->ID . '="{your secret}"'
                        )
                    );
                } else {
                    $fields->insertAfter(
                        'ClientID',
                        LiteralField::create(
                            'ClientSecretDescriptionDefined',
                            _t(
                                __CLASS__ . '.CLIENT_SECRET_DESCRIPTION_DEFINED',
                                '<p class="alert alert-success">' .
                                'Client secret is properly defined in your .env file.' .
                                '</p>'
                            )
                        )
                    );
                }

                $fields->insertAfter(
                    'Title',
                    ReadonlyField::create(
                        'CallbackURL',
                        $this->fieldLabel('CallbackURL'),
                        OAuth2::get_callback_url_for_provider($this)
                    )
                );

                $testLink = $this->getInitAuthFlowURL(true);

                $fields->addFieldToTab(
                    'Root.Main',
                    LiteralField::create(
                        'TestLinkButton',
                        '<p>' .
                        '<a href="' . $testLink . '" target="_blank">' .
                        _t(__CLASS__ . '.TEST_LINK', 'Test OAuth flow') .
                        '</a>' .
                        '<br/>' .
                        '<span class="text-muted">' .
                        _t(__CLASS__ . '.TEST_LINK_DESCRIPTION', 'No data will be written.') .
                        '</span>' .
                        '</p>'
                    )
                );

                if (($members = $fields->dataFieldByName('Members')) && ($members instanceof GridField)) {
                    $config = GridFieldConfig_RecordViewer::create()
                        ->addComponent(new GridFieldDeleteAction(true));

                    $members->setConfig($config);
                }
            }
        });

        return parent::getCMSFields();
    }

    /**
     * @param bool $includerelations
     * @return array
     */
    public function fieldLabels($includerelations = true): array
    {
        $labels = parent::fieldLabels($includerelations);
        $labels['Active'] = $labels['Active.Nice'] = _t(__CLASS__ . '.ACTIVE', 'Active');
        $labels['Title'] = _t(__CLASS__ . '.TITLE', 'Title');
        $labels['OpenIDDiscoveryEndpoint'] = _t(__CLASS__ . '.OPEN_ID_DISCOVERY_ENDPOINT', 'OpenID connect discovery endpoint');
        $labels['AuthorizationEndpoint'] = _t(__CLASS__ . '.AUTHORIZATION_ENDPOINT', 'Authorization endpoint');
        $labels['TokenEndpoint'] = _t(__CLASS__ . '.TOKEN_ENDPOINT', 'Token endpoint');
        $labels['UserInfoEndpoint'] = _t(__CLASS__ . '.USER_INFO_ENDPOINT', 'User info endpoint');
        $labels['UserInfoEmailPath'] = _t(__CLASS__ . '.USER_INFO_EMAIL_PATH', 'User info - path to email');
        $labels['UserInfoFirstNamePath'] = _t(
            __CLASS__ . '.USER_INFO_FIRST_NAME_PATH',
            'User info - path to first name'
        );
        $labels['UserInfoSurnamePath'] = _t(__CLASS__ . '.USER_INFO_SURNAME_PATH', 'User info - path to surname');
        $labels['GroupsInfoEndpoint'] = _t(__CLASS__ . '.GROUPS_INFO_ENDPOINT', 'Groups info endpoint');
        $labels['GroupsInfoIdentifierPath'] = _t(
            __CLASS__ . '.GROUPS_INFO_IDENTIFIER_PATH',
            'Groups info - path to unique group identifier (e.g. an id or unique string)'
        );
        $labels['ClientID'] = _t(__CLASS__ . '.CLIENT_ID', 'Client ID');
        $labels['ClientSecret'] = _t(__CLASS__ . '.CLIENT_SECRET', 'Client secret');
        $labels['CallbackURL'] = _t(__CLASS__ . '.CALLBACK_URL', 'Callback URL');
        $labels['Scopes'] = _t(__CLASS__ . '.SCOPES', 'Scopes to request');
        $labels['NewMembersDefaultGroupID'] = $labels['NewMembersDefaultGroup'] = _t(
            __CLASS__ . '.NEW_MEMBERS_DEFAULT_GROUP',
            'Add new members to'
        );
        $labels['IconID'] = $labels['Icon'] = _t(__CLASS__ . '.ICON', 'Icon');
        $labels['GroupMappings'] = GroupMapping::singleton()->i18n_plural_name();
        $labels['Members'] = Member::singleton()->i18n_plural_name();
        return $labels;
    }

    /**
     * @return ValidationResult
     */
    public function validate(): ValidationResult
    {
        $result = parent::validate();

        $requiredFields = [
            'Title',
            'UserInfoEmailPath',
        ];

        foreach ($requiredFields as $field) {
            if (empty($this->{$field})) {
                $result->addFieldError(
                    $field,
                    _t(__CLASS__ . '.ERROR_EMPTY_FIELD', 'This field is required')
                );
            }
        }

        if (empty($openIDDiscoveryEndpoint = $this->OpenIDDiscoveryEndpoint)) {
            $requiredFields = [
                'AuthorizationEndpoint',
                'TokenEndpoint',
                'UserInfoEndpoint',
            ];

            foreach ($requiredFields as $field) {
                if (empty($this->{$field})) {
                    $result->addFieldError(
                        $field,
                        _t(
                            __CLASS__ . '.ERROR_EMPTY_FIELD_ENDPOINTS',
                            'This field is required, if no OpenID connect discovery endpoint is defined.'
                        )
                    );
                }
            }
        }

        if ($result->isValid()) {
            $filterOptions = [
                FILTER_FLAG_PATH_REQUIRED,
            ];

            foreach (['AuthorizationEndpoint', 'TokenEndpoint'] as $field) {
                if (empty($value = $this->{$field})) {
                    continue;
                }
                if (!filter_var($value, FILTER_VALIDATE_URL, $filterOptions)) {
                    $result->addFieldError(
                        $field,
                        _t(__CLASS__ . '.ERROR_INVALID_URL', 'Invalid URL')
                    );
                }
            }

            foreach (['UserInfoEmailPath',] as $field) {
                if (!preg_match('/^\$\./', $this->{$field})) {
                    $result->addFieldError(
                        $field,
                        _t(__CLASS__ . '.ERROR_PATH', 'Path must start with $. .')
                    );
                }
            }
        }

        return $result;
    }

    /**
     * @return string
     */
    public function getClientSecretEnvKey(): string
    {
        if (!$this->exists()) {
            return '';
        }

        return 'OAUTH2_CLIENT_SECRET_PROVIDER_' . $this->ID;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        if (empty($secret = Environment::getEnv($this->getClientSecretEnvKey()))) {
            return '';
        }

        return (string)$secret;
    }

    /**
     * @param bool $test
     * @return string
     */
    public function getInitAuthFlowURL(bool $test = false): string
    {
        return OAuth2::get_init_auth_flow_url($this, $test);
    }

    /**
     * @return DataList
     */
    public static function get_available_provider(): DataList
    {
        return static::get()->filter(['Active' => true]);
    }

    /**
     * @return array|string[]
     */
    public static function get_template_global_variables(): array
    {
        return [
            'OAuth2Provider' => 'get_available_provider'
        ];
    }
}
