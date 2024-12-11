// Code generated by assertions generator; DO NOT EDIT.

package resourceassert

import (
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/acceptance/bettertestspoc/assert"
)

type FunctionJavaResourceAssert struct {
	*assert.ResourceAssert
}

func FunctionJavaResource(t *testing.T, name string) *FunctionJavaResourceAssert {
	t.Helper()

	return &FunctionJavaResourceAssert{
		ResourceAssert: assert.NewResourceAssert(name, "resource"),
	}
}

func ImportedFunctionJavaResource(t *testing.T, id string) *FunctionJavaResourceAssert {
	t.Helper()

	return &FunctionJavaResourceAssert{
		ResourceAssert: assert.NewImportedResourceAssert(id, "imported resource"),
	}
}

///////////////////////////////////
// Attribute value string checks //
///////////////////////////////////

func (f *FunctionJavaResourceAssert) HasArgumentsString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("arguments", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasCommentString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("comment", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasDatabaseString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("database", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasEnableConsoleOutputString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("enable_console_output", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasExternalAccessIntegrationsString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("external_access_integrations", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasFullyQualifiedNameString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("fully_qualified_name", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasFunctionDefinitionString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("function_definition", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasFunctionLanguageString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("function_language", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasHandlerString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("handler", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasImportsString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("imports", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasIsSecureString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("is_secure", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasLogLevelString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("log_level", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasMetricLevelString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("metric_level", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasNameString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("name", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasNullInputBehaviorString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("null_input_behavior", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasPackagesString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("packages", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasReturnBehaviorString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("return_behavior", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasReturnTypeString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("return_type", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasRuntimeVersionString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("runtime_version", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasSchemaString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("schema", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasSecretsString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("secrets", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasTargetPathString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("target_path", expected))
	return f
}

func (f *FunctionJavaResourceAssert) HasTraceLevelString(expected string) *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueSet("trace_level", expected))
	return f
}

////////////////////////////
// Attribute empty checks //
////////////////////////////

func (f *FunctionJavaResourceAssert) HasNoArguments() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("arguments"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoComment() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("comment"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoDatabase() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("database"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoEnableConsoleOutput() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("enable_console_output"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoExternalAccessIntegrations() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("external_access_integrations"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoFullyQualifiedName() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("fully_qualified_name"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoFunctionDefinition() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("function_definition"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoFunctionLanguage() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("function_language"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoHandler() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("handler"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoImports() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("imports"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoIsSecure() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("is_secure"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoLogLevel() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("log_level"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoMetricLevel() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("metric_level"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoName() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("name"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoNullInputBehavior() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("null_input_behavior"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoPackages() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("packages"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoReturnBehavior() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("return_behavior"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoReturnType() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("return_type"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoRuntimeVersion() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("runtime_version"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoSchema() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("schema"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoSecrets() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("secrets"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoTargetPath() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("target_path"))
	return f
}

func (f *FunctionJavaResourceAssert) HasNoTraceLevel() *FunctionJavaResourceAssert {
	f.AddAssertion(assert.ValueNotSet("trace_level"))
	return f
}
