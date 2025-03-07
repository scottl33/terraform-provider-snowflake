// Code generated by sdk-to-schema generator; DO NOT EDIT.

package schemas

import (
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ShowAccountSchema represents output of SHOW query for the single Account.
var ShowAccountSchema = map[string]*schema.Schema{
	"organization_name": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"account_name": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"region_group": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"snowflake_region": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"edition": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"account_url": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"created_on": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"comment": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"account_locator": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"account_locator_url": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"managed_accounts": {
		Type:     schema.TypeInt,
		Computed: true,
	},
	"consumption_billing_entity_name": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"marketplace_consumer_billing_entity_name": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"marketplace_provider_billing_entity_name": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"old_account_url": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"is_org_admin": {
		Type:     schema.TypeBool,
		Computed: true,
	},
}

var _ = ShowAccountSchema

func AccountToSchema(account *sdk.Account) map[string]any {
	accountSchema := make(map[string]any)
	accountSchema["organization_name"] = account.OrganizationName
	accountSchema["account_name"] = account.AccountName
	accountSchema["region_group"] = account.RegionGroup
	accountSchema["snowflake_region"] = account.SnowflakeRegion
	accountSchema["edition"] = account.Edition
	accountSchema["account_url"] = account.AccountURL
	accountSchema["created_on"] = account.CreatedOn.String()
	accountSchema["comment"] = account.Comment
	accountSchema["account_locator"] = account.AccountLocator
	accountSchema["account_locator_url"] = account.AccountLocatorURL
	accountSchema["managed_accounts"] = account.ManagedAccounts
	accountSchema["consumption_billing_entity_name"] = account.ConsumptionBillingEntityName
	accountSchema["marketplace_consumer_billing_entity_name"] = account.MarketplaceConsumerBillingEntityName
	accountSchema["marketplace_provider_billing_entity_name"] = account.MarketplaceProviderBillingEntityName
	accountSchema["old_account_url"] = account.OldAccountURL
	accountSchema["is_org_admin"] = account.IsOrgAdmin
	return accountSchema
}

var _ = AccountToSchema
