<?php

namespace BimTheBam\OAuth2Authenticator\Model\OAuth2;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ListboxField;
use SilverStripe\Forms\TextareaField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBText;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Group;

/**
 * Class GroupMapping
 * @package BimTheBam\OAuth2Authenticator\Model\OAuth2
 * @property string InternalTitle
 * @property string ExternalGroupIDs
 * @property int ProviderID
 * @method Provider Provider()
 * @method ManyManyList|Group[] Groups()
 * @property string GroupTitles
 */
class GroupMapping extends DataObject
{
    /**
     * @var string
     */
    private static string $table_name = 'OAuth2GroupMapping';

    /**
     * @var string
     */
    private static string $singular_name = 'Group mapping';

    /**
     * @var string
     */
    private static string $plural_name = 'Group mappings';

    /**
     * @var string[]
     */
    private static array $db = [
        'InternalTitle' => DBVarchar::class,
        'ExternalGroupIDs' => DBText::class,
    ];

    /**
     * @var string[]
     */
    private static array $has_one = [
        'Provider' => Provider::class,
    ];

    /**
     * @var string[]
     */
    private static array $many_many = [
        'Groups' => Group::class,
    ];

    /**
     * @var string[]
     */
    private static array $summary_fields = [
        'InternalTitle',
        'GroupTitles',
    ];

    /**
     * @return FieldList
     */
    public function getCMSFields(): FieldList
    {
        $this->beforeUpdateCMSFields(function (FieldList $fields) {
            $fields->removeByName([
                'ProviderID',
                'Groups',
            ]);

            if (($externalGroupIDs = $fields->dataFieldByName('ExternalGroupIDs'))) {
                if ($externalGroupIDs instanceof TextareaField) {
                    $externalGroupIDs->setRows(1);
                }

                $externalGroupIDs->setDescription(
                    _t(
                        __CLASS__ . '.EXTERNAL_GROUP_IDS_DESCRIPTION',
                        'Provide as comma separated list.'
                    )
                );
            }

            $fields->push(
                ListboxField::create('Groups', $this->fieldLabel('Groups'), $this->availableGroups())
            );
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
        $labels['InternalTitle'] = _t(__CLASS__ . '.INTERNAL_TITLE', 'Internal title');
        $labels['ExternalGroupIDs'] = _t(
            __CLASS__ . '.EXTERNAL_GROUP_IDS',
            'External group identifiers (e.g. ids or unique strings)'
        );
        $labels['Provider'] = $labels['ProviderID'] = Provider::singleton()->i18n_singular_name();
        $labels['Groups'] = _t(__CLASS__ . '.GROUPS', 'Map to internal groups');
        $labels['GroupTitles'] = Group::singleton()->i18n_plural_name();
        return $labels;
    }

    /**
     * @return ValidationResult
     */
    public function validate(): ValidationResult
    {
        $result = parent::validate();

        $errorEmptyField = _t(__CLASS__ . '.ERROR_EMPTY_FIELD', 'This field is required');

        if (empty(trim($this->ExternalGroupIDs))) {
            $result->addFieldError('ExternalGroupIDs', $errorEmptyField);
        }

        if (!$this->Groups()->count()) {
            $result->addFieldError('Groups', $errorEmptyField);
        }

        return $result;
    }

    /**
     * @return string
     */
    public function getGroupTitles(): string
    {
        return implode(
            ', ',
            array_values($this->Groups()->map('ID', 'Title')->toArray())
        );
    }

    /**
     * @param int $parentID
     * @param string|null $path
     * @return array
     */
    protected function availableGroups(int $parentID = 0, ?string $path = null): array
    {
        $groups = [];

        /** @var Group $group */
        foreach (Group::get()->filter(['ParentID' => $parentID]) as $group) {
            $groups[$group->ID] = trim($path . $group->Title);
            $childGroups = $this->availableGroups($group->ID, $path . $group->Title . ' > ');
            foreach ($childGroups as $childID => $childTitle) {
                $groups[$childID] = $childTitle;
            }
        }

        return $groups;
    }
}
