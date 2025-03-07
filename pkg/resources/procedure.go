package resources

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/internal/provider"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/provider/resources"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/schemas"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk/datatypes"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var procedureSchema = map[string]*schema.Schema{
	"name": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Specifies the identifier for the procedure; does not have to be unique for the schema in which the procedure is created. Don't use the | character.",
	},
	"database": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The database in which to create the procedure. Don't use the | character.",
		ForceNew:    true,
	},
	"schema": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The schema in which to create the procedure. Don't use the | character.",
		ForceNew:    true,
	},
	"secure": {
		Type:        schema.TypeBool,
		Optional:    true,
		Description: "Specifies that the procedure is secure. For more information about secure procedures, see Protecting Sensitive Information with Secure UDFs and Stored Procedures.",
		Default:     false,
	},
	"arguments": {
		Type: schema.TypeList,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					// Suppress the diff shown if the values are equal when both compared in lower case.
					DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
						return strings.EqualFold(old, new)
					},
					Description: "The argument name",
				},
				"type": {
					Type:             schema.TypeString,
					Required:         true,
					Description:      "The argument type",
					ValidateDiagFunc: IsDataTypeValid,
					DiffSuppressFunc: DiffSuppressDataTypes,
				},
			},
		},
		Optional:    true,
		Description: "List of the arguments for the procedure",
		ForceNew:    true,
	},
	"return_type": {
		Type:        schema.TypeString,
		Description: "The return type of the procedure",
		// Suppress the diff shown if the values are equal when both compared in lower case.
		DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
			if strings.EqualFold(old, new) {
				return true
			}

			varcharType := []string{"VARCHAR(16777216)", "VARCHAR", "text", "string", "NVARCHAR", "NVARCHAR2", "CHAR VARYING", "NCHAR VARYING"}
			if slices.Contains(varcharType, strings.ToUpper(old)) && slices.Contains(varcharType, strings.ToUpper(new)) {
				return true
			}

			// all these types are equivalent https://docs.snowflake.com/en/sql-reference/data-types-numeric.html#int-integer-bigint-smallint-tinyint-byteint
			integerTypes := []string{"INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "BYTEINT", "NUMBER(38,0)"}
			if slices.Contains(integerTypes, strings.ToUpper(old)) && slices.Contains(integerTypes, strings.ToUpper(new)) {
				return true
			}
			return false
		},
		Required: true,
		ForceNew: true,
	},
	"statement": {
		Type:             schema.TypeString,
		Required:         true,
		Description:      "Specifies the code used to create the procedure.",
		ForceNew:         true,
		DiffSuppressFunc: DiffSuppressStatement,
	},
	"language": {
		Type:     schema.TypeString,
		Optional: true,
		Default:  "SQL",
		DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
			return strings.EqualFold(old, new)
		},
		ValidateFunc: validation.StringInSlice([]string{"javascript", "java", "scala", "SQL", "python"}, true),
		Description:  "Specifies the language of the stored procedure code.",
	},
	"execute_as": {
		Type:     schema.TypeString,
		Optional: true,
		Default:  "OWNER",
		DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
			return strings.EqualFold(old, new)
		},
		ValidateFunc: validation.StringInSlice([]string{"CALLER", "OWNER"}, true),
		Description:  "Sets execution context. Allowed values are CALLER and OWNER (consult a proper section in the [docs](https://docs.snowflake.com/en/sql-reference/sql/create-procedure#id1)). For more information see [caller's rights and owner's rights](https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-rights).",
	},
	"null_input_behavior": {
		Type:     schema.TypeString,
		Optional: true,
		Default:  "CALLED ON NULL INPUT",
		ForceNew: true,
		// We do not use STRICT, because Snowflake then in the Read phase returns RETURNS NULL ON NULL INPUT
		ValidateFunc: validation.StringInSlice([]string{"CALLED ON NULL INPUT", "RETURNS NULL ON NULL INPUT"}, false),
		Description:  "Specifies the behavior of the procedure when called with null inputs.",
	},
	"return_behavior": {
		Type:         schema.TypeString,
		Optional:     true,
		Default:      "VOLATILE",
		ForceNew:     true,
		ValidateFunc: validation.StringInSlice([]string{"VOLATILE", "IMMUTABLE"}, false),
		Description:  "Specifies the behavior of the function when returning results",
		Deprecated:   "These keywords are deprecated for stored procedures. These keywords are not intended to apply to stored procedures. In a future release, these keywords will be removed from the documentation.",
	},
	"comment": {
		Type:        schema.TypeString,
		Optional:    true,
		Default:     "user-defined procedure",
		Description: "Specifies a comment for the procedure.",
	},
	"runtime_version": {
		Type:        schema.TypeString,
		Optional:    true,
		ForceNew:    true,
		Description: "Required for Python procedures. Specifies Python runtime version.",
	},
	"packages": {
		Type: schema.TypeList,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		ForceNew:    true,
		Description: "List of package imports to use for Java / Python procedures. For Java, package imports should be of the form: package_name:version_number, where package_name is snowflake_domain:package. For Python use it should be: ('numpy','pandas','xgboost==1.5.0').",
	},
	"imports": {
		Type: schema.TypeList,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Optional:    true,
		ForceNew:    true,
		Description: "Imports for Java / Python procedures. For Java this a list of jar files, for Python this is a list of Python files.",
	},
	"handler": {
		Type:        schema.TypeString,
		Optional:    true,
		ForceNew:    true,
		Description: "The handler method for Java / Python procedures.",
	},
	FullyQualifiedNameAttributeName: schemas.FullyQualifiedNameSchema,
}

// Procedure returns a pointer to the resource representing a stored procedure.
func Procedure() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 2,

		CreateContext: TrackingCreateWrapper(resources.Procedure, CreateContextProcedure),
		ReadContext:   TrackingReadWrapper(resources.Procedure, ReadContextProcedure),
		UpdateContext: TrackingUpdateWrapper(resources.Procedure, UpdateContextProcedure),
		DeleteContext: TrackingDeleteWrapper(resources.Procedure, DeleteContextProcedure),

		// TODO(SNOW-1348106): add `arguments` to ComputedIfAnyAttributeChanged for FullyQualifiedNameAttributeName.
		// This can't be done now because this function compares values without diff suppress.
		CustomizeDiff: TrackingCustomDiffWrapper(resources.Procedure, customdiff.All(
			ComputedIfAnyAttributeChanged(procedureSchema, FullyQualifiedNameAttributeName, "name"),
		)),

		Schema: procedureSchema,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				// setting type to cty.EmptyObject is a bit hacky here but following https://developer.hashicorp.com/terraform/plugin/framework/migrating/resources/state-upgrade#sdkv2-1 would require lots of repetitive code; this should work with cty.EmptyObject
				Type:    cty.EmptyObject,
				Upgrade: v085ProcedureStateUpgrader,
			},
			{
				Version: 1,
				// setting type to cty.EmptyObject is a bit hacky here but following https://developer.hashicorp.com/terraform/plugin/framework/migrating/resources/state-upgrade#sdkv2-1 would require lots of repetitive code; this should work with cty.EmptyObject
				Type:    cty.EmptyObject,
				Upgrade: v0941ResourceIdentifierWithArguments,
			},
		},
	}
}

func CreateContextProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lang := strings.ToUpper(d.Get("language").(string))
	switch lang {
	case "JAVA":
		return createJavaProcedure(ctx, d, meta)
	case "JAVASCRIPT":
		return createJavaScriptProcedure(ctx, d, meta)
	case "PYTHON":
		return createPythonProcedure(ctx, d, meta)
	case "SCALA":
		return createScalaProcedure(ctx, d, meta)
	case "SQL":
		return createSQLProcedure(ctx, d, meta)
	default:
		return diag.Diagnostics{
			diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Invalid language",
				Detail:   fmt.Sprintf("Language %s is not supported", lang),
			},
		}
	}
}

func createJavaProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	sc := d.Get("schema").(string)
	database := d.Get("database").(string)
	args, diags := getProcedureArguments(d)
	if diags != nil {
		return diags
	}
	argDataTypes := make([]sdk.DataType, len(args))
	for i, arg := range args {
		argDataTypes[i] = arg.ArgDataTypeOld
	}
	id := sdk.NewSchemaObjectIdentifierWithArguments(database, sc, name, argDataTypes...)

	returns, diags := parseProcedureReturnsRequest(d.Get("return_type").(string))
	if diags != nil {
		return diags
	}
	procedureDefinition := d.Get("statement").(string)
	runtimeVersion := d.Get("runtime_version").(string)
	packages := make([]sdk.ProcedurePackageRequest, 0)
	for _, item := range d.Get("packages").([]interface{}) {
		packages = append(packages, *sdk.NewProcedurePackageRequest(item.(string)))
	}
	handler := d.Get("handler").(string)
	req := sdk.NewCreateForJavaProcedureRequest(id.SchemaObjectId(), *returns, runtimeVersion, packages, handler)
	req.WithProcedureDefinition(procedureDefinition)
	if len(args) > 0 {
		req.WithArguments(args)
	}

	// read optional params
	if v, ok := d.GetOk("execute_as"); ok {
		if strings.ToUpper(v.(string)) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(v.(string)) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
	}
	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}
	if v, ok := d.GetOk("secure"); ok {
		req.WithSecure(v.(bool))
	}
	if _, ok := d.GetOk("imports"); ok {
		var imports []sdk.ProcedureImportRequest
		for _, item := range d.Get("imports").([]interface{}) {
			imports = append(imports, *sdk.NewProcedureImportRequest(item.(string)))
		}
		req.WithImports(imports)
	}

	if err := client.Procedures.CreateForJava(ctx, req); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id.FullyQualifiedName())
	return ReadContextProcedure(ctx, d, meta)
}

func createJavaScriptProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	sc := d.Get("schema").(string)
	database := d.Get("database").(string)
	args, diags := getProcedureArguments(d)
	if diags != nil {
		return diags
	}
	argDataTypes := make([]sdk.DataType, len(args))
	for i, arg := range args {
		argDataTypes[i] = arg.ArgDataTypeOld
	}
	id := sdk.NewSchemaObjectIdentifierWithArguments(database, sc, name, argDataTypes...)

	returnType := d.Get("return_type").(string)
	returnDataType, diags := convertProcedureDataType(returnType)
	if diags != nil {
		return diags
	}
	procedureDefinition := d.Get("statement").(string)
	req := sdk.NewCreateForJavaScriptProcedureRequest(id.SchemaObjectId(), nil, procedureDefinition).WithResultDataTypeOld(sdk.LegacyDataTypeFrom(returnDataType))
	if len(args) > 0 {
		req.WithArguments(args)
	}

	// read optional params
	if v, ok := d.GetOk("execute_as"); ok {
		if strings.ToUpper(v.(string)) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(v.(string)) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
	}
	if v, ok := d.GetOk("null_input_behavior"); ok {
		req.WithNullInputBehavior(sdk.NullInputBehavior(v.(string)))
	}
	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}
	if v, ok := d.GetOk("secure"); ok {
		req.WithSecure(v.(bool))
	}

	if err := client.Procedures.CreateForJavaScript(ctx, req); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id.FullyQualifiedName())
	return ReadContextProcedure(ctx, d, meta)
}

func createScalaProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	sc := d.Get("schema").(string)
	database := d.Get("database").(string)
	args, diags := getProcedureArguments(d)
	if diags != nil {
		return diags
	}
	argDataTypes := make([]sdk.DataType, len(args))
	for i, arg := range args {
		argDataTypes[i] = arg.ArgDataTypeOld
	}
	id := sdk.NewSchemaObjectIdentifierWithArguments(database, sc, name, argDataTypes...)

	returns, diags := parseProcedureReturnsRequest(d.Get("return_type").(string))
	if diags != nil {
		return diags
	}
	procedureDefinition := d.Get("statement").(string)
	runtimeVersion := d.Get("runtime_version").(string)
	packages := make([]sdk.ProcedurePackageRequest, 0)
	for _, item := range d.Get("packages").([]interface{}) {
		packages = append(packages, *sdk.NewProcedurePackageRequest(item.(string)))
	}
	handler := d.Get("handler").(string)
	req := sdk.NewCreateForScalaProcedureRequest(id.SchemaObjectId(), *returns, runtimeVersion, packages, handler)
	req.WithProcedureDefinition(procedureDefinition)
	if len(args) > 0 {
		req.WithArguments(args)
	}

	// read optional params
	if v, ok := d.GetOk("execute_as"); ok {
		if strings.ToUpper(v.(string)) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(v.(string)) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
	}
	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}
	if v, ok := d.GetOk("secure"); ok {
		req.WithSecure(v.(bool))
	}
	if _, ok := d.GetOk("imports"); ok {
		var imports []sdk.ProcedureImportRequest
		for _, item := range d.Get("imports").([]interface{}) {
			imports = append(imports, *sdk.NewProcedureImportRequest(item.(string)))
		}
		req.WithImports(imports)
	}

	if err := client.Procedures.CreateForScala(ctx, req); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id.FullyQualifiedName())
	return ReadContextProcedure(ctx, d, meta)
}

func createSQLProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	sc := d.Get("schema").(string)
	database := d.Get("database").(string)
	args, diags := getProcedureArguments(d)
	if diags != nil {
		return diags
	}
	argDataTypes := make([]sdk.DataType, len(args))
	for i, arg := range args {
		argDataTypes[i] = arg.ArgDataTypeOld
	}
	id := sdk.NewSchemaObjectIdentifierWithArguments(database, sc, name, argDataTypes...)

	returns, diags := parseProcedureSQLReturnsRequest(d.Get("return_type").(string))
	if diags != nil {
		return diags
	}
	procedureDefinition := d.Get("statement").(string)
	req := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, procedureDefinition)
	if len(args) > 0 {
		req.WithArguments(args)
	}

	// read optional params
	if v, ok := d.GetOk("execute_as"); ok {
		if strings.ToUpper(v.(string)) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(v.(string)) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
	}
	if v, ok := d.GetOk("null_input_behavior"); ok {
		req.WithNullInputBehavior(sdk.NullInputBehavior(v.(string)))
	}
	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}
	if v, ok := d.GetOk("secure"); ok {
		req.WithSecure(v.(bool))
	}

	if err := client.Procedures.CreateForSQL(ctx, req); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id.FullyQualifiedName())
	return ReadContextProcedure(ctx, d, meta)
}

func createPythonProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client
	name := d.Get("name").(string)
	sc := d.Get("schema").(string)
	database := d.Get("database").(string)
	args, diags := getProcedureArguments(d)
	if diags != nil {
		return diags
	}
	argDataTypes := make([]sdk.DataType, len(args))
	for i, arg := range args {
		argDataTypes[i] = arg.ArgDataTypeOld
	}
	id := sdk.NewSchemaObjectIdentifierWithArguments(database, sc, name, argDataTypes...)

	returns, diags := parseProcedureReturnsRequest(d.Get("return_type").(string))
	if diags != nil {
		return diags
	}
	procedureDefinition := d.Get("statement").(string)
	runtimeVersion := d.Get("runtime_version").(string)
	packages := make([]sdk.ProcedurePackageRequest, 0)
	for _, item := range d.Get("packages").([]interface{}) {
		packages = append(packages, *sdk.NewProcedurePackageRequest(item.(string)))
	}
	handler := d.Get("handler").(string)
	req := sdk.NewCreateForPythonProcedureRequest(id.SchemaObjectId(), *returns, runtimeVersion, packages, handler)
	req.WithProcedureDefinition(procedureDefinition)
	if len(args) > 0 {
		req.WithArguments(args)
	}

	// read optional params
	if v, ok := d.GetOk("execute_as"); ok {
		if strings.ToUpper(v.(string)) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(v.(string)) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
	}

	// [ { CALLED ON NULL INPUT | { RETURNS NULL ON NULL INPUT | STRICT } } ] does not work for java, scala or python
	// posted in docs-discuss channel, either docs need to be updated to reflect reality or this feature needs to be added
	// https://snowflake.slack.com/archives/C6380540P/p1707511734666249
	// if v, ok := d.GetOk("null_input_behavior"); ok {
	// 	req.WithNullInputBehavior(sdk.Pointer(sdk.NullInputBehavior(v.(string))))
	// }

	if v, ok := d.GetOk("comment"); ok {
		req.WithComment(v.(string))
	}
	if v, ok := d.GetOk("secure"); ok {
		req.WithSecure(v.(bool))
	}
	if _, ok := d.GetOk("imports"); ok {
		var imports []sdk.ProcedureImportRequest
		for _, item := range d.Get("imports").([]interface{}) {
			imports = append(imports, *sdk.NewProcedureImportRequest(item.(string)))
		}
		req.WithImports(imports)
	}

	if err := client.Procedures.CreateForPython(ctx, req); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id.FullyQualifiedName())
	return ReadContextProcedure(ctx, d, meta)
}

func ReadContextProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	diags := diag.Diagnostics{}
	client := meta.(*provider.Context).Client

	id, err := sdk.ParseSchemaObjectIdentifierWithArguments(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(FullyQualifiedNameAttributeName, id.FullyQualifiedName()); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("name", id.Name()); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("database", id.DatabaseName()); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("schema", id.SchemaName()); err != nil {
		return diag.FromErr(err)
	}
	args := d.Get("arguments").([]interface{})
	argTypes := make([]string, len(args))
	for i, arg := range args {
		argTypes[i] = arg.(map[string]interface{})["type"].(string)
	}
	procedureDetails, err := client.Procedures.Describe(ctx, id)
	if err != nil {
		// if procedure is not found then mark resource to be removed from state file during apply or refresh
		d.SetId("")
		return diag.Diagnostics{
			diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Describe procedure failed.",
				Detail:   fmt.Sprintf("Describe procedure failed: %v", err),
			},
		}
	}
	for _, desc := range procedureDetails {
		switch desc.Property {
		case "signature":
			// Format in Snowflake DB is: (argName argType, argName argType, ...)
			args := strings.ReplaceAll(strings.ReplaceAll(desc.Value, "(", ""), ")", "")

			if args != "" { // Do nothing for functions without arguments
				argPairs := strings.Split(args, ", ")
				var args []any

				for _, argPair := range argPairs {
					argItem := strings.Split(argPair, " ")

					arg := map[string]interface{}{}
					arg["name"] = argItem[0]
					arg["type"] = argItem[1]
					args = append(args, arg)
				}

				if err := d.Set("arguments", args); err != nil {
					return diag.FromErr(err)
				}
			}
		case "null handling":
			if err := d.Set("null_input_behavior", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "body":
			if err := d.Set("statement", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "execute as":
			if err := d.Set("execute_as", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "returns":
			if err := d.Set("return_type", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "language":
			if err := d.Set("language", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "runtime_version":
			if err := d.Set("runtime_version", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "packages":
			packagesString := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(desc.Value, "[", ""), "]", ""), "'", "")
			if packagesString != "" { // Do nothing for Java / Python functions without packages
				packages := strings.Split(packagesString, ",")
				if err := d.Set("packages", packages); err != nil {
					return diag.FromErr(err)
				}
			}
		case "imports":
			importsString := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(desc.Value, "[", ""), "]", ""), "'", ""), " ", "")
			if importsString != "" { // Do nothing for Java functions without imports
				imports := strings.Split(importsString, ",")
				if err := d.Set("imports", imports); err != nil {
					return diag.FromErr(err)
				}
			}
		case "handler":
			if err := d.Set("handler", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		case "volatility":
			if err := d.Set("return_behavior", desc.Value); err != nil {
				return diag.FromErr(err)
			}
		default:
			log.Printf("[INFO] Unexpected procedure property %v returned from Snowflake with value %v", desc.Property, desc.Value)
		}
	}

	procedure, err := client.Procedures.ShowByID(ctx, id)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("secure", procedure.IsSecure); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("comment", procedure.Description); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func UpdateContextProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client

	id, err := sdk.ParseSchemaObjectIdentifierWithArguments(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("name") {
		newId := sdk.NewSchemaObjectIdentifier(id.DatabaseName(), id.SchemaName(), d.Get("name").(string))
		newIdWithArguments := sdk.NewSchemaObjectIdentifierWithArguments(id.DatabaseName(), id.SchemaName(), d.Get("name").(string), id.ArgumentDataTypes()...)

		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithRenameTo(newId.WithoutArguments()))
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId(newIdWithArguments.FullyQualifiedName())
		id = newIdWithArguments
	}

	if d.HasChange("comment") {
		comment := d.Get("comment")
		if comment != "" {
			if err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithSetComment(comment.(string))); err != nil {
				return diag.FromErr(err)
			}
		} else {
			if err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithUnsetComment(true)); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	if d.HasChange("execute_as") {
		req := sdk.NewAlterProcedureRequest(id)
		executeAs := d.Get("execute_as").(string)
		if strings.ToUpper(executeAs) == "OWNER" {
			req.WithExecuteAs(sdk.ExecuteAsOwner)
		} else if strings.ToUpper(executeAs) == "CALLER" {
			req.WithExecuteAs(sdk.ExecuteAsCaller)
		}
		if err := client.Procedures.Alter(ctx, req); err != nil {
			return diag.FromErr(err)
		}
	}

	return ReadContextProcedure(ctx, d, meta)
}

func DeleteContextProcedure(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.Context).Client

	id, err := sdk.ParseSchemaObjectIdentifierWithArguments(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	if err := client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id).WithIfExists(true)); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func getProcedureArguments(d *schema.ResourceData) ([]sdk.ProcedureArgumentRequest, diag.Diagnostics) {
	args := make([]sdk.ProcedureArgumentRequest, 0)
	if v, ok := d.GetOk("arguments"); ok {
		for _, arg := range v.([]interface{}) {
			argName := arg.(map[string]interface{})["name"].(string)
			argType := arg.(map[string]interface{})["type"].(string)
			argDataType, diags := convertProcedureDataType(argType)
			if diags != nil {
				return nil, diags
			}
			args = append(args, sdk.ProcedureArgumentRequest{ArgName: argName, ArgDataTypeOld: sdk.LegacyDataTypeFrom(argDataType)})
		}
	}
	return args, nil
}

func convertProcedureDataType(s string) (datatypes.DataType, diag.Diagnostics) {
	dataType, err := datatypes.ParseDataType(s)
	if err != nil {
		return nil, diag.FromErr(err)
	}
	return dataType, nil
}

func convertProcedureColumns(s string) ([]sdk.ProcedureColumn, diag.Diagnostics) {
	pattern := regexp.MustCompile(`(\w+)\s+(\w+)`)
	matches := pattern.FindAllStringSubmatch(s, -1)
	var columns []sdk.ProcedureColumn
	for _, match := range matches {
		if len(match) == 3 {
			dataType, err := datatypes.ParseDataType(match[2])
			if err != nil {
				return nil, diag.FromErr(err)
			}
			columns = append(columns, sdk.ProcedureColumn{
				ColumnName:        match[1],
				ColumnDataTypeOld: sdk.LegacyDataTypeFrom(dataType),
			})
		}
	}
	return columns, nil
}

func parseProcedureReturnsRequest(s string) (*sdk.ProcedureReturnsRequest, diag.Diagnostics) {
	returns := sdk.NewProcedureReturnsRequest()
	if strings.HasPrefix(strings.ToLower(s), "table") {
		columns, diags := convertProcedureColumns(s)
		if diags != nil {
			return nil, diags
		}
		var cr []sdk.ProcedureColumnRequest
		for _, item := range columns {
			cr = append(cr, *sdk.NewProcedureColumnRequest(item.ColumnName, nil).WithColumnDataTypeOld(item.ColumnDataTypeOld))
		}
		returns.WithTable(*sdk.NewProcedureReturnsTableRequest().WithColumns(cr))
	} else {
		returnDataType, diags := convertProcedureDataType(s)
		if diags != nil {
			return nil, diags
		}
		returns.WithResultDataType(*sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.LegacyDataTypeFrom(returnDataType)))
	}
	return returns, nil
}

func parseProcedureSQLReturnsRequest(s string) (*sdk.ProcedureSQLReturnsRequest, diag.Diagnostics) {
	returns := sdk.NewProcedureSQLReturnsRequest()
	if strings.HasPrefix(strings.ToLower(s), "table") {
		columns, diags := convertProcedureColumns(s)
		if diags != nil {
			return nil, diags
		}
		var cr []sdk.ProcedureColumnRequest
		for _, item := range columns {
			cr = append(cr, *sdk.NewProcedureColumnRequest(item.ColumnName, nil).WithColumnDataTypeOld(item.ColumnDataTypeOld))
		}
		returns.WithTable(*sdk.NewProcedureReturnsTableRequest().WithColumns(cr))
	} else {
		returnDataType, diags := convertProcedureDataType(s)
		if diags != nil {
			return nil, diags
		}
		returns.WithResultDataType(*sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.LegacyDataTypeFrom(returnDataType)))
	}
	return returns, nil
}
