package resources

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/helpers"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/internal/provider"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var oauthIntegrationForCustomClientsSchema = map[string]*schema.Schema{
	"name": {
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "Specifies the name of the OAuth integration. This name follows the rules for Object Identifiers. The name should be unique among security integrations in your account.",
	},
	"oauth_client_type": {
		Type:         schema.TypeString,
		Required:     true,
		Description:  fmt.Sprintf("Specifies the type of client being registered. Snowflake supports both confidential and public clients. Valid options are: %v", sdk.AllOauthSecurityIntegrationClientTypes),
		ValidateFunc: validation.StringInSlice(sdk.AsStringList(sdk.AllOauthSecurityIntegrationClientTypes), true),
	},
	"oauth_redirect_uri": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Specifies the client URI. After a user is authenticated, the web browser is redirected to this URI.",
	},
	"enabled": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Specifies whether this OAuth integration is enabled or disabled.",
	},
	"oauth_allow_non_tls_redirect_uri": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "If true, allows setting oauth_redirect_uri to a URI not protected by TLS.",
	},
	"oauth_enforce_pkce": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Boolean that specifies whether Proof Key for Code Exchange (PKCE) should be required for the integration.",
	},
	"oauth_use_secondary_roles": {
		Type:         schema.TypeString,
		Optional:     true,
		Description:  fmt.Sprintf("Specifies whether default secondary roles set in the user properties are activated by default in the session being opened. Valid options are: %v", sdk.AllOauthSecurityIntegrationUseSecondaryRoles),
		ValidateFunc: validation.StringInSlice(sdk.AsStringList(sdk.AllOauthSecurityIntegrationUseSecondaryRoles), true),
		DiffSuppressFunc: func(k, oldValue, newValue string, d *schema.ResourceData) bool {
			return d.Get(k).(string) == string(sdk.OauthSecurityIntegrationUseSecondaryRolesNone) && newValue == ""
		},
	},
	"pre_authorized_roles_list": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "Comma-separated list of Snowflake roles that a user does not need to explicitly consent to using after authenticating.",
	},
	"blocked_roles_list": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Optional:    true,
		Description: "Comma-separated list of Snowflake roles that a user cannot explicitly consent to using after authenticating.",
	},
	"oauth_issue_refresh_tokens": {
		Type:        schema.TypeBool,
		Optional:    true,
		Computed:    true,
		Description: "Specifies whether to allow the client to exchange a refresh token for an access token when the current access token has expired.",
	},
	"oauth_refresh_token_validity": {
		Type:        schema.TypeInt,
		Optional:    true,
		Description: "Specifies how long refresh tokens should be valid (in seconds). OAUTH_ISSUE_REFRESH_TOKENS must be set to TRUE.",
	},
	"network_policy": {
		Type:     schema.TypeString,
		Optional: true,
		Description: "Specifies an existing network policy. This network policy controls network traffic that is attempting to exchange an authorization " +
			"code for an access or refresh token or to use a refresh token to obtain a new access token.",
		DiffSuppressFunc: func(_, old, new string, d *schema.ResourceData) bool {
			return sdk.NewAccountObjectIdentifierFromFullyQualifiedName(old) == sdk.NewAccountObjectIdentifierFromFullyQualifiedName(new)
		},
	},
	"oauth_client_rsa_public_key": {
		Type:        schema.TypeString,
		Optional:    true,
		Computed:    true,
		Description: "Hash of `oauth_client_rsa_public_key` returned from Snowflake.",
	},
	// "oauth_client_rsa_public_key_config_hash": {
	// 	Type:        schema.TypeString,
	// 	Computed:    true,
	// 	Description: "Hash of `oauth_client_rsa_public_key` returned from Snowflake.",
	// },
	"oauth_client_rsa_public_key_fingerprint": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Fingerprint of `oauth_client_rsa_public_key` returned from Snowflake.",
	},
	"oauth_client_rsa_public_key_2": {
		Type:        schema.TypeString,
		Optional:    true,
		Computed:    true,
		Description: "Hash of `oauth_client_rsa_public_key` returned from Snowflake.",
	},
	"oauth_client_rsa_public_key_2_config_hash": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Hash of `oauth_client_rsa_public_key` returned from Snowflake.",
	},
	"oauth_client_rsa_public_key_2_snowflake_hash": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Hash of `oauth_client_rsa_public_key` returned from Snowflake.",
	},
	"oauth_authorization_endpoint": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Authorization endpoint for oauth.",
	},
	"oauth_token_endpoint": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Token endpoint for oauth.",
	},
	"oauth_allowed_authorization_endpoints": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Computed:    true,
		Description: "A list of allowed authorization endpoints for oauth.",
	},
	"oauth_allowed_token_endpoints": {
		Type:        schema.TypeSet,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Computed:    true,
		Description: "A list of allowed token endpoints for oauth.",
	},
	"comment": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Specifies a comment for the OAuth integration.",
	},
	"created_on": {
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Date and time when the OAuth integration was created.",
	},
}

func OauthIntegrationForCustomClients() *schema.Resource {
	return &schema.Resource{
		CreateContext: CreateContextOauthIntegrationForCustomClients,
		ReadContext:   f(true),
		UpdateContext: UpdateContextOauthIntegrationForCustomClients,
		DeleteContext: DeleteContextSecurityIntegration,
		Schema:        oauthIntegrationForCustomClientsSchema,
		// CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
		// 	if d.Get("oauth_client_rsa_public_key_fingerprint") != d.Get("oauth_client_rsa_public_key_config_hash") {
		// 		return d.SetNewComputed("oauth_client_rsa_public_key")
		// 	}
		// 	return nil
		// },
		// CustomizeDiff: BoolComputedIf("oauth_issue_refresh_tokens", func(client *sdk.Client, id sdk.AccountObjectIdentifier) (string, error) {
		// 	props, err := client.SecurityIntegrations.Describe(context.Background(), id)
		// 	if err != nil {
		// 		return "", err
		// 	}
		// 	for _, prop := range props {
		// 		if prop.GetName() == "OAUTH_ISSUE_REFRESH_TOKENS" {
		// 			return prop.GetDefault(), nil
		// 		}
		// 	}
		// 	return "", fmt.Errorf("")
		// }),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func CreateContextOauthIntegrationForCustomClients(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	oauthClientTypeRaw := d.Get("oauth_client_type").(string)
	oauthClientType, err := sdk.ToOauthSecurityIntegrationClientTypeOption(oauthClientTypeRaw)
	if err != nil {
		return diag.FromErr(err)
	}
	oauthRedirectUri := d.Get("oauth_redirect_uri").(string)
	id := sdk.NewAccountObjectIdentifier(name)
	req := sdk.NewCreateOauthForCustomClientsSecurityIntegrationRequest(id, oauthClientType, oauthRedirectUri)

	if v, ok := d.GetOk("blocked_roles_list"); ok {
		elems := expandStringList(v.(*schema.Set).List())
		blockedRoles := make([]sdk.AccountObjectIdentifier, len(elems))
		for i := range elems {
			blockedRoles[i] = sdk.NewAccountObjectIdentifier(elems[i])
		}
		req.WithBlockedRolesList(sdk.BlockedRolesListRequest{BlockedRolesList: blockedRoles})
	}

	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}

	if v, ok := d.GetOk("enabled"); ok {
		req.WithEnabled(v.(bool))
	}

	if v, ok := d.GetOk("network_policy"); ok {
		req.WithNetworkPolicy(sdk.NewAccountObjectIdentifier(v.(string)))
	}

	if v, ok := d.GetOk("oauth_allow_non_tls_redirect_uri"); ok {
		req.WithOauthAllowNonTlsRedirectUri(v.(bool))
	}

	if v, ok := d.GetOk("oauth_client_rsa_public_key"); ok {
		req.WithOauthClientRsaPublicKey(v.(string))
	}

	if v, ok := d.GetOk("oauth_client_rsa_public_key_2"); ok {
		req.WithOauthClientRsaPublicKey2(v.(string))
	}

	if v, ok := d.GetOk("oauth_enforce_pkce"); ok {
		req.WithOauthEnforcePkce(v.(bool))
	}

	if v, ok := d.GetOk("oauth_issue_refresh_tokens"); ok {
		req.WithOauthIssueRefreshTokens(v.(bool))
	}

	if v, ok := d.GetOk("oauth_refresh_token_validity"); ok {
		req.WithOauthRefreshTokenValidity(v.(int))
	}

	if v, ok := d.GetOk("oauth_use_secondary_roles"); ok {
		oauthUseSecondaryRoles, err := sdk.ToOauthSecurityIntegrationUseSecondaryRolesOption(v.(string))
		if err != nil {
			return diag.FromErr(err)
		}
		req.WithOauthUseSecondaryRoles(oauthUseSecondaryRoles)
	}

	if v, ok := d.GetOk("pre_authorized_roles_list"); ok {
		elems := expandStringList(v.(*schema.Set).List())
		preAuthorizedRoles := make([]sdk.AccountObjectIdentifier, len(elems))
		for i := range elems {
			preAuthorizedRoles[i] = sdk.NewAccountObjectIdentifier(elems[i])
		}
		req.WithPreAuthorizedRolesList(sdk.PreAuthorizedRolesListRequest{PreAuthorizedRolesList: preAuthorizedRoles})
	}

	if err := client.SecurityIntegrations.CreateOauthForCustomClients(ctx, req); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)
	return f(false)(ctx, d, meta)
}

func f(expectExternalChanges bool) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		client := meta.(*provider.Context).Client
		id := helpers.DecodeSnowflakeID(d.Id()).(sdk.AccountObjectIdentifier)
		// params, err := client.Parameters.ShowParameters(ctx, &sdk.ShowParametersOptions{
		// 	Like: &sdk.Like{
		// 		Pattern: sdk.Pointer("OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST"),
		// 	},
		// })
		// param := params[0]

		integration, err := client.SecurityIntegrations.ShowByID(ctx, id)
		if err != nil {
			if errors.Is(err, sdk.ErrObjectNotFound) {
				d.SetId("")
				return diag.Diagnostics{
					diag.Diagnostic{
						Severity: diag.Warning,
						Summary:  "Failed to query security integration. Marking the resource as removed.",
						Detail:   fmt.Sprintf("Security integration name: %s, Err: %s", id.FullyQualifiedName(), err),
					},
				}
			}
			return diag.FromErr(err)
		}
		if c := integration.Category; c != sdk.SecurityIntegrationCategory {
			return diag.FromErr(fmt.Errorf("expected %v to be a %s integration, got %v", id, sdk.SecurityIntegrationCategory, c))
		}

		if err := d.Set("name", integration.Name); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set("comment", integration.Comment); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set("created_on", integration.CreatedOn.String()); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set("enabled", integration.Enabled); err != nil {
			return diag.FromErr(err)
		}
		properties, err := client.SecurityIntegrations.Describe(ctx, id)
		if err != nil {
			return diag.FromErr(err)
		}
		for _, property := range properties {
			name := property.Name
			value := property.Value
			switch name {
			case "BLOCKED_ROLES_LIST":
				var blockedRoles []string
				if len(value) > 0 {
					blockedRoles = strings.Split(value, ",")
				}

				if err := d.Set("blocked_roles_list", blockedRoles); err != nil {
					return diag.FromErr(err)
				}
			case "COMMENT":
				if err := d.Set("comment", value); err != nil {
					return diag.FromErr(err)
				}
			case "CREATED_ON":
				if err := d.Set("created_on", value); err != nil {
					return diag.FromErr(err)
				}
			case "ENABLED":
				if err := d.Set("enabled", helpers.StringToBool(value)); err != nil {
					return diag.FromErr(err)
				}
			case "NETWORK_POLICY":
				if err := d.Set("network_policy", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_ALLOW_NON_TLS_REDIRECT_URI":
				if err := d.Set("oauth_allow_non_tls_redirect_uri", helpers.StringToBool(value)); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_CLIENT_RSA_PUBLIC_KEY_FP":
				if expectExternalChanges {
					key := d.Get("oauth_client_rsa_public_key").(string)
					configValue, err := RSAKeyHash(key)
					if err != nil {
						return diag.FromErr(err)
					}
					if configValue != value {
						if err := d.Set("oauth_client_rsa_public_key", "<changed outside terraform>"); err != nil {
							return diag.FromErr(err)
						}
					}
				}
				if err := d.Set("oauth_client_rsa_public_key_fingerprint", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_CLIENT_RSA_PUBLIC_KEY_2_FP":
				if expectExternalChanges {
					configValue := d.Get("oauth_client_rsa_public_key_2_config_hash").(string)
					if configValue != value {
						if err := d.Set("oauth_client_rsa_public_key_2", "<changed outside terraform>"); err != nil {
							return diag.FromErr(err)
						}
					}
				} else {
					if err := d.Set("oauth_client_rsa_public_key_2_config_hash", value); err != nil {
						return diag.FromErr(err)
					}
				}
				if err := d.Set("oauth_client_rsa_public_key_2_snowflake_hash", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_CLIENT_TYPE":
				if err := d.Set("oauth_client_type", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_ENFORCE_PKCE":
				if err := d.Set("oauth_enforce_pkce", helpers.StringToBool(value)); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_ISSUE_REFRESH_TOKENS":
				if err := d.Set("oauth_issue_refresh_tokens", helpers.StringToBool(value)); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_REDIRECT_URI":
				if err := d.Set("oauth_redirect_uri", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_REFRESH_TOKEN_VALIDITY":
				num, err := strconv.Atoi(value)
				if err != nil {
					return diag.FromErr(err)
				}
				if err := d.Set("oauth_refresh_token_validity", num); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_USE_SECONDARY_ROLES":
				if err := d.Set("oauth_use_secondary_roles", value); err != nil {
					return diag.FromErr(err)
				}
			case "PRE_AUTHORIZED_ROLES_LIST":
				var preAuthorizedRoles []string
				if len(value) > 0 {
					preAuthorizedRoles = strings.Split(value, ",")
				}

				if err := d.Set("pre_authorized_roles_list", preAuthorizedRoles); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_AUTHORIZATION_ENDPOINT":
				if err := d.Set("oauth_authorization_endpoint", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_TOKEN_ENDPOINT":
				if err := d.Set("oauth_token_endpoint", value); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_ALLOWED_AUTHORIZATION_ENDPOINTS":
				var elems []string
				if len(value) > 0 {
					elems = strings.Split(value, ",")
				}

				if err := d.Set("oauth_allowed_authorization_endpoints", elems); err != nil {
					return diag.FromErr(err)
				}
			case "OAUTH_ALLOWED_TOKEN_ENDPOINTS":
				var elems []string
				if len(value) > 0 {
					elems = strings.Split(value, ",")
				}
				if err := d.Set("oauth_allowed_token_endpoints", elems); err != nil {
					return diag.FromErr(err)
				}
			default:
				log.Printf("[WARN] unexpected property %v returned from Snowflake", name)
			}
		}

		return nil
	}
}

func UpdateContextOauthIntegrationForCustomClients(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	id := helpers.DecodeSnowflakeID(d.Id()).(sdk.AccountObjectIdentifier)
	set, unset := sdk.NewOauthForCustomClientsIntegrationSetRequest(), sdk.NewOauthForCustomClientsIntegrationUnsetRequest()

	if d.HasChange("blocked_roles_list") {
		elems := expandStringList(d.Get("blocked_roles_list").(*schema.Set).List())
		blockedRoles := make([]sdk.AccountObjectIdentifier, len(elems))
		for i := range elems {
			blockedRoles[i] = sdk.NewAccountObjectIdentifier(elems[i])
		}
		set.WithBlockedRolesList(sdk.BlockedRolesListRequest{BlockedRolesList: blockedRoles})
	}

	if d.HasChange("comment") {
		set.WithComment(d.Get("comment").(string))
	}

	if d.HasChange("enabled") {
		set.WithEnabled(d.Get("enabled").(bool))
	}

	if d.HasChange("network_policy") {
		set.WithNetworkPolicy(sdk.NewAccountObjectIdentifier(d.Get("network_policy").(string)))
	}

	if d.HasChange("oauth_allow_non_tls_redirect_uri") {
		set.WithOauthAllowNonTlsRedirectUri(d.Get("oauth_allow_non_tls_redirect_uri").(bool))
	}

	if d.HasChange("oauth_client_rsa_public_key") {
		set.WithOauthClientRsaPublicKey(d.Get("oauth_client_rsa_public_key").(string))
	}

	if d.HasChange("oauth_client_rsa_public_key_2") {
		set.WithOauthClientRsaPublicKey2(d.Get("oauth_client_rsa_public_key_2").(string))
	}

	if d.HasChange("oauth_enforce_pkce") {
		set.WithOauthEnforcePkce(d.Get("oauth_enforce_pkce").(bool))
	}

	if d.HasChange("oauth_issue_refresh_tokens") {
		set.WithOauthIssueRefreshTokens(d.Get("oauth_issue_refresh_tokens").(bool))
	}

	if d.HasChange("oauth_redirect_uri") {
		set.WithOauthRedirectUri(d.Get("oauth_redirect_uri").(string))
	}

	if d.HasChange("oauth_refresh_token_validity") {
		set.WithOauthRefreshTokenValidity(d.Get("oauth_refresh_token_validity").(int))
	}

	if d.HasChange("oauth_use_secondary_roles") {
		oauthUseSecondaryRoles, err := sdk.ToOauthSecurityIntegrationUseSecondaryRolesOption(d.Get("oauth_use_secondary_roles").(string))
		if err != nil {
			return diag.FromErr(err)
		}
		set.WithOauthUseSecondaryRoles(oauthUseSecondaryRoles)
	}

	if d.HasChange("pre_authorized_roles_list") {
		elems := expandStringList(d.Get("pre_authorized_roles_list").(*schema.Set).List())
		preAuthorizedRoles := make([]sdk.AccountObjectIdentifier, len(elems))
		for i := range elems {
			preAuthorizedRoles[i] = sdk.NewAccountObjectIdentifier(elems[i])
		}
		set.WithPreAuthorizedRolesList(sdk.PreAuthorizedRolesListRequest{PreAuthorizedRolesList: preAuthorizedRoles})
	}

	if !reflect.DeepEqual(*set, sdk.OauthForCustomClientsIntegrationSetRequest{}) {
		if err := client.SecurityIntegrations.AlterOauthForCustomClients(ctx, sdk.NewAlterOauthForCustomClientsSecurityIntegrationRequest(id).WithSet(*set)); err != nil {
			return diag.FromErr(err)
		}
	}
	if !reflect.DeepEqual(*unset, sdk.OauthForCustomClientsIntegrationUnsetRequest{}) {
		if err := client.SecurityIntegrations.AlterOauthForCustomClients(ctx, sdk.NewAlterOauthForCustomClientsSecurityIntegrationRequest(id).WithUnset(*unset)); err != nil {
			return diag.FromErr(err)
		}
	}
	return f(false)(ctx, d, meta)
}
