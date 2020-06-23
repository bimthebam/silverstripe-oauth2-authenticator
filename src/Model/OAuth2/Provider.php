<?php

namespace BimTheBam\OAuth2Authenticator\Model\OAuth2;

use BimTheBam\OAuth2Authenticator\Control\OAuth2;
use SilverStripe\Core\Environment;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\TextareaField;
use SilverStripe\Forms\TreeDropdownField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBBoolean;
use SilverStripe\ORM\FieldType\DBText;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\Security\Group;

/**
 * Class Provider
 * @package BimTheBam\OAuth2Authenticator\Model\OAuth2
 * @property bool Active
 * @property string Title
 * @property string AuthorizationEndpoint
 * @property string TokenEndpoint
 * @property string UserInfoEndpoint
 * @property string UserInfoEmailPath
 * @property string UserInfoFirstNamePath
 * @property string UserInfoSurnamePath
 * @property string ClientID
 * @property string Scopes
 * @property int NewMembersDefaultGroupID
 * @method Group NewMembersDefaultGroup()
 * @property string ClientSecretEnvKey
 * @property string ClientSecret
 */
class Provider extends DataObject
{
    /**
     * @var string[]
     */
    private static $db = [
        'Active' => DBBoolean::class,
        'Title' => DBVarchar::class . '(50)',
        'AuthorizationEndpoint' => DBVarchar::class . '(255)',
        'TokenEndpoint' => DBVarchar::class . '(255)',
        'UserInfoEndpoint' => DBVarchar::class . '(255)',
        'UserInfoEmailPath' => DBVarchar::class . '(255)',
        'UserInfoFirstNamePath' => DBVarchar::class . '(255)',
        'UserInfoSurnamePath' => DBVarchar::class . '(255)',
        'ClientID' => DBText::class,
        'Scopes' => DBVarchar::class . '(255)',
    ];

    /**
     * @var string[]
     */
    private static $has_one = [
        'NewMembersDefaultGroup' => Group::class,
    ];

    /**
     * @var string[]
     */
    private static $summary_fields = [
        'Active.Nice',
        'Title',
    ];

    /**
     * @return FieldList
     */
    public function getCMSFields()
    {
        $this->beforeUpdateCMSFields(function (FieldList $fields) {
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

            $pathDescriptionPlain = _t(
                __CLASS__ . '.PATH_DESCRIPTION_PLAIN',
                'e.g. $.variable' .
                '<br/>' .
                ' (see <a href="https://github.com/FlowCommunications/JSONPath#jsonpath-examples" target="_blank">' .
                'https://github.com/FlowCommunications/JSONPath#jsonpath-examples</a> for examples)'
            );

            foreach (['UserInfoEmailPath', 'UserInfoFirstNamePath', 'UserInfoSurnamePath'] as $field) {
                if (($field = $fields->dataFieldByName($field))) {
                    $field->setDescription($pathDescriptionPlain)
                        ->setAttribute('placeholder', 'body.fieldName');
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

            if ($this->exists()) {
                if (empty($this->ClientSecret)) {
                    $fields->insertAfter(
                        'ClientID',
                        LiteralField::create(
                            'ClientSecretDescription',
                            _t(
                                __CLASS__ . '.CLIENT_SECRET_DESCRIPTION',
                                '<p class="alert alert-info">' .
                                'The client secrect must be stored secretly. ' .
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
                                '<p class="alert alert-info">' .
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

                $testLink = OAuth2::get_init_auth_flow_url($this, true);

                $fields->push(
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
            }
        });

        return parent::getCMSFields(); // TODO: Change the autogenerated stub
    }

    /**
     * @param bool $includerelations
     * @return array
     */
    public function fieldLabels($includerelations = true)
    {
        $labels = parent::fieldLabels($includerelations);
        $labels['Active'] = $labels['Active.Nice'] = _t(__CLASS__ . '.ACTIVE', 'Active');
        $labels['Title'] = _t(__CLASS__ . '.TITLE', 'Title');
        $labels['AuthorizationEndpoint'] = _t(__CLASS__ . '.AUTHORIZATION_ENDPOINT', 'Authorization endpoint');
        $labels['TokenEndpoint'] = _t(__CLASS__ . '.TOKEN_ENDPOINT', 'Token endpoint');
        $labels['UserInfoEndpoint'] = _t(__CLASS__ . '.USER_INFO_ENDPOINT', 'User info endpoint');
        $labels['UserInfoEmailPath'] = _t(__CLASS__ . '.USER_INFO_EMAIL_PATH', 'User info - path to email');
        $labels['UserInfoFirstNamePath'] = _t(
            __CLASS__ . '.USER_INFO_FIRST_NAME_PATH',
            'User info - path to first name'
        );
        $labels['UserInfoSurnamePath'] = _t(__CLASS__ . '.USER_INFO_SURNAME_PATH', 'User info - path to surname');
        $labels['ClientID'] = _t(__CLASS__ . '.CLIENT_ID', 'Client ID');
        $labels['ClientSecret'] = _t(__CLASS__ . '.CLIENT_SECRET', 'Client secret');
        $labels['CallbackURL'] = _t(__CLASS__ . '.CALLBACK_URL', 'Callback URL');
        $labels['Scopes'] = _t(__CLASS__ . '.SCOPES', 'Scopes to request');
        $labels['NewMembersDefaultGroupID'] = $labels['NewMembersDefaultGroup'] = _t(
            __CLASS__ . '.NEW_MEMBERS_DEFAULT_GROUP',
            'Add new members to'
        );
        return $labels;
    }

    /**
     * @return \SilverStripe\ORM\ValidationResult
     */
    public function validate()
    {
        $result = parent::validate();

        $requiredFields = [
            'Title',
            'AuthorizationEndpoint',
            'TokenEndpoint',
            'UserInfoEndpoint',
            'UserInfoEmailPath',
            'UserInfoFirstNamePath',
            'UserInfoSurnamePath',
        ];

        foreach ($requiredFields as $field) {
            if (empty($this->{$field})) {
                $result->addFieldError(
                    $field,
                    _t(__CLASS__ . '.ERROR_EMPTY_FIELD', 'This field is required')
                );
            }
        }

        if ($result->isValid()) {
            $filterOptions = [
                FILTER_FLAG_SCHEME_REQUIRED,
                FILTER_FLAG_HOST_REQUIRED,
                FILTER_FLAG_PATH_REQUIRED,
            ];

            foreach (['AuthorizationEndpoint', 'TokenEndpoint'] as $field) {
                if (!filter_var($this->{$field}, FILTER_VALIDATE_URL, $filterOptions)) {
                    $result->addFieldError(
                        $field,
                        _t(__CLASS__ . '.ERROR_INVALID_URL', 'Invalid URL')
                    );
                }
            }

            foreach (['UserInfoEmailPath', 'UserInfoFirstNamePath', 'UserInfoSurnamePath'] as $field) {
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
    public function getClientSecretEnvKey()
    {
        if (!$this->exists()) {
            return '';
        }

        return 'OAUTH2_CLIENT_SECRET_PROVIDER_' . $this->ID;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        if (empty($secret = Environment::getEnv($this->getClientSecretEnvKey()))) {
            return '';
        }

        return (string)$secret;
    }
}
