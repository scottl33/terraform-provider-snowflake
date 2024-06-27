package resources_test

import (
	"context"
	"fmt"
	"testing"

	acc "github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/acceptance"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/acceptance/helpers"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/acceptance/helpers/random"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAcc_OauthIntegrationForCustomClients_basic(t *testing.T) {
	networkPolicy, networkPolicyCleanup := acc.TestClient().NetworkPolicy.CreateNetworkPolicy(t)
	t.Cleanup(networkPolicyCleanup)
	validUrl := "https://example.com"
	id := acc.TestClient().Ids.RandomAccountObjectIdentifier()
	key, _ := random.GenerateRSAPublicKey(t)

	m := func(complete bool) map[string]config.Variable {
		c := map[string]config.Variable{
			"name":               config.StringVariable(id.Name()),
			"oauth_client_type":  config.StringVariable(string(sdk.OauthSecurityIntegrationClientTypeConfidential)),
			"oauth_redirect_uri": config.StringVariable(validUrl),
		}
		if complete {
			c["blocked_roles_list"] = config.SetVariable(config.StringVariable("foo"))
			c["comment"] = config.StringVariable("foo")
			c["created_on"] = config.StringVariable("foo")
			c["enabled"] = config.BoolVariable(true)
			c["network_policy"] = config.StringVariable(networkPolicy.Name)
			c["oauth_allow_non_tls_redirect_uri"] = config.BoolVariable(true)
			c["oauth_allowed_authorization_endpoints"] = config.SetVariable(config.StringVariable("foo"))
			c["oauth_allowed_token_endpoints"] = config.SetVariable(config.StringVariable("foo"))
			c["oauth_authorization_endpoint"] = config.StringVariable("foo")
			c["oauth_client_rsa_public_key"] = config.StringVariable(key)
			c["oauth_client_rsa_public_key_2"] = config.StringVariable(key)
			c["oauth_enforce_pkce"] = config.BoolVariable(true)
			c["oauth_issue_refresh_tokens"] = config.BoolVariable(true)
			c["oauth_refresh_token_validity"] = config.IntegerVariable(42)
			c["oauth_token_endpoint"] = config.StringVariable("foo")
			c["oauth_use_secondary_roles"] = config.StringVariable("foo")
			c["pre_authorized_roles_list"] = config.SetVariable(config.StringVariable("foo"))
		}
		return c
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acc.TestAccProtoV6ProviderFactories,
		PreCheck:                 func() { acc.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.RequireAbove(tfversion.Version1_5_0),
		},
		Steps: []resource.TestStep{
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/basic"),
				ConfigVariables: m(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "name", id.Name()),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_type", string(sdk.OauthSecurityIntegrationClientTypeConfidential)),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_redirect_uri", validUrl),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "created_on"),
				),
			},
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables: m(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "blocked_roles_list.#", "1"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "comment", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "created_on", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "enabled", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "name", id.Name()),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "network_policy", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allow_non_tls_redirect_uri", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_authorization_endpoints", "[]"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_token_endpoints", ""),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_authorization_endpoint", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", key),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", key),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_type", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_enforce_pkce", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_issue_refresh_tokens", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_redirect_uri", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_refresh_token_validity", "42"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_token_endpoint", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_use_secondary_roles", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "pre_authorized_roles_list", "[]"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "created_on"),
				),
			},
			{
				ConfigDirectory:   acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/basic"),
				ConfigVariables:   m(true),
				ResourceName:      "snowflake_oauth_integration_for_custom_clients.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// unset
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/basic"),
				ConfigVariables: m(false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "blocked_roles_list", "[]"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "comment", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "created_on", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "enabled", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "name", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "network_policy", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allow_non_tls_redirect_uri", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_authorization_endpoints", "[]"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_token_endpoints", "[]"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_authorization_endpoint", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_type", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_enforce_pkce", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_issue_refresh_tokens", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_redirect_uri", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_refresh_token_validity", "42"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_token_endpoint", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_use_secondary_roles", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "pre_authorized_roles_list", "[]"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "created_on"),
				),
			},
		},
	})
}

func TestAcc_OauthIntegrationForCustomClients_rsaPublicKeysFlow(t *testing.T) {
	id := acc.TestClient().Ids.RandomAccountObjectIdentifier()
	networkPolicy, networkPolicyCleanup := acc.TestClient().NetworkPolicy.CreateNetworkPolicy(t)
	t.Cleanup(networkPolicyCleanup)
	role1, role1Cleanup := acc.TestClient().Role.CreateRole(t)
	t.Cleanup(role1Cleanup)
	role2, role2Cleanup := acc.TestClient().Role.CreateRole(t)
	t.Cleanup(role2Cleanup)

	key1, key1Hash := random.GenerateRSAPublicKey(t)
	key2, key2Hash := random.GenerateRSAPublicKey(t)

	m := func(key string) map[string]config.Variable {
		return map[string]config.Variable{
			"blocked_roles_list":               config.SetVariable(config.StringVariable(role1.ID().Name())),
			"comment":                          config.StringVariable("foo"),
			"enabled":                          config.BoolVariable(true),
			"name":                             config.StringVariable(id.Name()),
			"network_policy":                   config.StringVariable(networkPolicy.Name),
			"oauth_allow_non_tls_redirect_uri": config.BoolVariable(true),
			"oauth_client_rsa_public_key":      config.StringVariable(key),
			"oauth_client_rsa_public_key_2":    config.StringVariable(key),
			"oauth_client_type":                config.StringVariable(string(sdk.OauthSecurityIntegrationClientTypeConfidential)),
			"oauth_enforce_pkce":               config.BoolVariable(true),
			"oauth_issue_refresh_tokens":       config.BoolVariable(true),
			"oauth_redirect_uri":               config.StringVariable("https://example.com"),
			"oauth_refresh_token_validity":     config.IntegerVariable(12345),
			"oauth_use_secondary_roles":        config.StringVariable(string(sdk.OauthSecurityIntegrationUseSecondaryRolesImplicit)),
			"pre_authorized_roles_list":        config.SetVariable(config.StringVariable(role2.ID().Name())),
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acc.TestAccProtoV6ProviderFactories,
		PreCheck:                 func() { acc.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.RequireAbove(tfversion.Version1_5_0),
		},
		Steps: []resource.TestStep{
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables: m(key1),
				Check: resource.ComposeTestCheckFunc(
					// func(d *terraform.State) error {
					// 	sfHash := d.RootModule().Resources["snowflake_oauth_integration_for_custom_clients.test"].Primary.Attributes["oauth_client_rsa_public_key_fingerprint"]
					// 	key1Hash = sfHash
					// 	return nil
					// },

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "blocked_roles_list.#", "1"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "blocked_roles_list.0", role1.ID().Name()),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "comment", "foo"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "enabled", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "name", id.Name()),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "network_policy", networkPolicy.Name),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_allow_non_tls_redirect_uri", "true"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_authorization_endpoints.#"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "oauth_allowed_token_endpoints.#"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "oauth_authorization_endpoint"),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", key1),
					// resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_config_hash", &key1Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_fingerprint", &key1Hash),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", key1),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_config_hash", &key1Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_snowflake_hash", &key1Hash),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_type", string(sdk.OauthSecurityIntegrationClientTypeConfidential)),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_enforce_pkce", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_issue_refresh_tokens", "true"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_redirect_uri", "https://example.com"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_refresh_token_validity", "12345"),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "oauth_token_endpoint"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_use_secondary_roles", string(sdk.OauthSecurityIntegrationUseSecondaryRolesImplicit)),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "pre_authorized_roles_list.#", "1"),
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "pre_authorized_roles_list.0", role2.ID().Name()),
					resource.TestCheckResourceAttrSet("snowflake_oauth_integration_for_custom_clients.test", "created_on"),
				),
			},
			{
				ConfigDirectory:   acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables:   m(key1),
				ResourceName:      "snowflake_oauth_integration_for_custom_clients.test",
				ImportState:       true,
				ImportStateVerify: true,
				// ignore because values are defined in config only
				ImportStateVerifyIgnore: []string{"oauth_client_rsa_public_key", "oauth_client_rsa_public_key_config_hash", "oauth_client_rsa_public_key_2", "oauth_client_rsa_public_key_2_config_hash"},
			},
			// change keys in config
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables: m(key2),
				Check: resource.ComposeTestCheckFunc(
					// func(d *terraform.State) error {
					// 	sfHash := d.RootModule().Resources["snowflake_oauth_integration_for_custom_clients.test"].Primary.Attributes["oauth_client_rsa_public_key_fingerprint"]
					// 	key2Hash = sfHash
					// 	return nil
					// },
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", key2),
					// resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_fingerprint", &key2Hash),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", key2),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_snowflake_hash", &key2Hash),
				),
			},
			// change keys outside terraform

			{
				PreConfig: func() {
					err := acc.Client(t).SecurityIntegrations.AlterOauthForCustomClients(context.Background(), sdk.NewAlterOauthForCustomClientsSecurityIntegrationRequest(id).WithSet(*sdk.NewOauthForCustomClientsIntegrationSetRequest().WithOauthClientRsaPublicKey(key1)))
					require.NoError(t, err)

					err = acc.Client(t).SecurityIntegrations.AlterOauthForCustomClients(context.Background(), sdk.NewAlterOauthForCustomClientsSecurityIntegrationRequest(id).WithSet(*sdk.NewOauthForCustomClientsIntegrationSetRequest().WithOauthClientRsaPublicKey2(key1)))
					require.NoError(t, err)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", "<changed outside terraform>"),
					// resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_fingerprint", &key1Hash),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", "<changed outside terraform>"),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_snowflake_hash", &key1Hash),
				),
			},
			// revert back to old key
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables: m(key2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key", key2),
					// resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_fingerprint", &key2Hash),

					resource.TestCheckResourceAttr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2", key2),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_config_hash", &key2Hash),
					resource.TestCheckResourceAttrPtr("snowflake_oauth_integration_for_custom_clients.test", "oauth_client_rsa_public_key_2_snowflake_hash", &key1Hash),
				),
			},
		},
	})
}

func TestAcc_OauthIntegrationForCustomClients_invalid(t *testing.T) {
	m := func() map[string]config.Variable {
		return map[string]config.Variable{
			"blocked_roles_list":                    config.SetVariable(config.StringVariable("foo")),
			"comment":                               config.StringVariable("foo"),
			"enabled":                               config.BoolVariable(true),
			"name":                                  config.StringVariable("foo"),
			"network_policy":                        config.StringVariable("foo"),
			"oauth_allow_non_tls_redirect_uri":      config.BoolVariable(true),
			"oauth_allowed_authorization_endpoints": config.SetVariable(config.StringVariable("foo")),
			"oauth_allowed_token_endpoints":         config.SetVariable(config.StringVariable("foo")),
			"oauth_authorization_endpoint":          config.StringVariable("foo"),
			"oauth_client_rsa_public_key":           config.StringVariable("foo"),
			"oauth_client_rsa_public_key_2":         config.StringVariable("foo"),
			"oauth_client_type":                     config.StringVariable("invalid"),
			"oauth_enforce_pkce":                    config.BoolVariable(true),
			"oauth_issue_refresh_tokens":            config.BoolVariable(true),
			"oauth_redirect_uri":                    config.StringVariable("foo"),
			"oauth_refresh_token_validity":          config.IntegerVariable(42),
			"oauth_token_endpoint":                  config.StringVariable("foo"),
			"oauth_use_secondary_roles":             config.StringVariable("invalid"),
			"pre_authorized_roles_list":             config.SetVariable(config.StringVariable("foo")),
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acc.TestAccProtoV6ProviderFactories,
		PreCheck:                 func() { acc.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.RequireAbove(tfversion.Version1_5_0),
		},
		ErrorCheck: helpers.AssertErrorContainsPartsFunc(t, []string{
			fmt.Sprintf(`expected oauth_client_type to be one of %q, got invalid`, sdk.AllOauthSecurityIntegrationClientTypes),
			fmt.Sprintf(`expected oauth_use_secondary_roles to be one of %q, got invalid`, sdk.AllOauthSecurityIntegrationUseSecondaryRoles),
		}),
		Steps: []resource.TestStep{
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/complete"),
				ConfigVariables: m(),
			},
		},
	})
}

func TestAcc_OauthIntegrationForCustomClients_InvalidIncomplete(t *testing.T) {
	m := func() map[string]config.Variable {
		return map[string]config.Variable{
			"name": config.StringVariable("foo"),
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acc.TestAccProtoV6ProviderFactories,
		PreCheck:                 func() { acc.TestAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.RequireAbove(tfversion.Version1_5_0),
		},
		ErrorCheck: helpers.AssertErrorContainsPartsFunc(t, []string{
			`The argument "oauth_client_type" is required, but no definition was found.`,
			`The argument "oauth_redirect_uri" is required, but no definition was found.`,
		}),
		Steps: []resource.TestStep{
			{
				ConfigDirectory: acc.ConfigurationDirectory("TestAcc_OauthIntegrationForCustomClients/invalid"),
				ConfigVariables: m(),
			},
		},
	})
}
