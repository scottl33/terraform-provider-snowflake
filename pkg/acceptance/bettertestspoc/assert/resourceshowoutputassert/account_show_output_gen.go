// Code generated by assertions generator; DO NOT EDIT.

package resourceshowoutputassert

import (
	"testing"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/acceptance/bettertestspoc/assert"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
)

// to ensure sdk package is used
var _ = sdk.Object{}

type AccountShowOutputAssert struct {
	*assert.ResourceAssert
}

func AccountShowOutput(t *testing.T, name string) *AccountShowOutputAssert {
	t.Helper()

	a := AccountShowOutputAssert{
		ResourceAssert: assert.NewResourceAssert(name, "show_output"),
	}
	a.AddAssertion(assert.ValueSet("show_output.#", "1"))
	return &a
}

func ImportedAccountShowOutput(t *testing.T, id string) *AccountShowOutputAssert {
	t.Helper()

	a := AccountShowOutputAssert{
		ResourceAssert: assert.NewImportedResourceAssert(id, "show_output"),
	}
	a.AddAssertion(assert.ValueSet("show_output.#", "1"))
	return &a
}

////////////////////////////
// Attribute value checks //
////////////////////////////

func (a *AccountShowOutputAssert) HasOrganizationName(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("organization_name", expected))
	return a
}

func (a *AccountShowOutputAssert) HasAccountName(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_name", expected))
	return a
}

func (a *AccountShowOutputAssert) HasSnowflakeRegion(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("snowflake_region", expected))
	return a
}

func (a *AccountShowOutputAssert) HasRegionGroup(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("region_group", expected))
	return a
}

func (a *AccountShowOutputAssert) HasEdition(expected sdk.AccountEdition) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputStringUnderlyingValueSet("edition", expected))
	return a
}

func (a *AccountShowOutputAssert) HasAccountURL(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_url", expected))
	return a
}

func (a *AccountShowOutputAssert) HasCreatedOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("created_on", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasComment(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("comment", expected))
	return a
}

func (a *AccountShowOutputAssert) HasAccountLocator(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_locator", expected))
	return a
}

func (a *AccountShowOutputAssert) HasAccountLocatorURL(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_locator_url", expected))
	return a
}

func (a *AccountShowOutputAssert) HasManagedAccounts(expected int) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputIntValueSet("managed_accounts", expected))
	return a
}

func (a *AccountShowOutputAssert) HasConsumptionBillingEntityName(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("consumption_billing_entity_name", expected))
	return a
}

func (a *AccountShowOutputAssert) HasMarketplaceConsumerBillingEntityName(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("marketplace_consumer_billing_entity_name", expected))
	return a
}

func (a *AccountShowOutputAssert) HasMarketplaceProviderBillingEntityName(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("marketplace_provider_billing_entity_name", expected))
	return a
}

func (a *AccountShowOutputAssert) HasOldAccountURL(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("old_account_url", expected))
	return a
}

func (a *AccountShowOutputAssert) HasIsOrgAdmin(expected bool) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputBoolValueSet("is_org_admin", expected))
	return a
}

func (a *AccountShowOutputAssert) HasAccountOldUrlSavedOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_old_url_saved_on", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasAccountOldUrlLastUsed(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("account_old_url_last_used", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasOrganizationOldUrl(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("organization_old_url", expected))
	return a
}

func (a *AccountShowOutputAssert) HasOrganizationOldUrlSavedOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("organization_old_url_saved_on", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasOrganizationOldUrlLastUsed(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("organization_old_url_last_used", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasIsEventsAccount(expected bool) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputBoolValueSet("is_events_account", expected))
	return a
}

func (a *AccountShowOutputAssert) HasIsOrganizationAccount(expected bool) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputBoolValueSet("is_organization_account", expected))
	return a
}

func (a *AccountShowOutputAssert) HasDroppedOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("dropped_on", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasScheduledDeletionTime(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("scheduled_deletion_time", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasRestoredOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("restored_on", expected.String()))
	return a
}

func (a *AccountShowOutputAssert) HasMovedToOrganization(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("moved_to_organization", expected))
	return a
}

func (a *AccountShowOutputAssert) HasMovedOn(expected string) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("moved_on", expected))
	return a
}

func (a *AccountShowOutputAssert) HasOrganizationUrlExpirationOn(expected time.Time) *AccountShowOutputAssert {
	a.AddAssertion(assert.ResourceShowOutputValueSet("organization_url_expiration_on", expected.String()))
	return a
}
