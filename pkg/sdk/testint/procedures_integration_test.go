package testint

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/internal/collections"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk/datatypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// todo: add tests for:
//  - creating procedure with different languages from stages

func TestInt_CreateProcedures(t *testing.T) {
	client := testClient(t)
	ctx := testContext(t)

	cleanupProcedureHandle := func(id sdk.SchemaObjectIdentifierWithArguments) func() {
		return func() {
			err := client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id))
			if errors.Is(err, sdk.ErrObjectNotExistOrAuthorized) {
				return
			}
			require.NoError(t, err)
		}
	}

	t.Run("create procedure for Java: returns result data type", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-java#reading-a-dynamically-specified-file-with-inputstream
		name := "file_reader_java_proc_snowflakefile"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR)

		definition := `
			import java.io.InputStream;
			import java.io.IOException;
			import java.nio.charset.StandardCharsets;
			import com.snowflake.snowpark_java.types.SnowflakeFile;
			import com.snowflake.snowpark_java.Session;
			class FileReader {
				public String execute(Session session, String fileName) throws IOException {
					InputStream input = SnowflakeFile.newInstance(fileName).getInputStream();
					return new String(input.readAllBytes(), StandardCharsets.UTF_8);
				}
			}`

		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureReturnsRequest().WithResultDataType(*dt)
		argument := sdk.NewProcedureArgumentRequest("input", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForJavaProcedureRequest(id.SchemaObjectId(), *returns, "11", packages, "FileReader.execute").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForJava(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Java: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-java#specifying-return-column-names-and-types
		name := "filter_by_role"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
			import com.snowflake.snowpark_java.*;
			public class Filter {
				public DataFrame filterByRole(Session session, String tableName, String role) {
					DataFrame table = session.table(tableName);
					DataFrame filteredRows = table.filter(Functions.col("role").equal_to(Functions.lit(role)));
					return filteredRows;
				}
			}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("table_name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForJavaProcedureRequest(id.SchemaObjectId(), *returns, "11", packages, "Filter.filterByRole").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForJava(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Javascript", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-javascript#basic-examples
		name := "stproc1"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeFloat)

		definition := `
				var sql_command = "INSERT INTO stproc_test_table1 (num_col1) VALUES (" + FLOAT_PARAM1 + ")";
				try {
					snowflake.execute (
						{sqlText: sql_command}
					);
					return "Succeeded."; // Return a success/error indicator.
				}
				catch (err)  {
					return "Failed: " + err; // Return a success/error indicator.
				}`
		argument := sdk.NewProcedureArgumentRequest("FLOAT_PARAM1", nil).WithArgDataTypeOld(sdk.DataTypeFloat)
		request := sdk.NewCreateForJavaScriptProcedureRequest(id.SchemaObjectId(), nil, definition).
			WithResultDataTypeOld(sdk.DataTypeString).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithNullInputBehavior(*sdk.NullInputBehaviorPointer(sdk.NullInputBehaviorStrict)).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsCaller))
		err := client.Procedures.CreateForJavaScript(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Javascript: no arguments", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-javascript#basic-examples
		name := "sp_pi"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name)

		definition := `return 3.1415926;`
		request := sdk.NewCreateForJavaScriptProcedureRequest(id.SchemaObjectId(), nil, definition).WithResultDataTypeOld(sdk.DataTypeFloat).WithNotNull(true).WithOrReplace(true)
		err := client.Procedures.CreateForJavaScript(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Scala: returns result data type", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-scala#reading-a-dynamically-specified-file-with-snowflakefile
		name := "file_reader_scala_proc_snowflakefile"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR)

		definition := `
			import java.io.InputStream
			import java.nio.charset.StandardCharsets
			import com.snowflake.snowpark_java.types.SnowflakeFile
			import com.snowflake.snowpark_java.Session
			object FileReader {
				def execute(session: Session, fileName: String): String = {
					var input: InputStream = SnowflakeFile.newInstance(fileName).getInputStream()
					return new String(input.readAllBytes(), StandardCharsets.UTF_8)
				}
			}`
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureReturnsRequest().WithResultDataType(*dt)
		argument := sdk.NewProcedureArgumentRequest("input", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForScalaProcedureRequest(id.SchemaObjectId(), *returns, "2.12", packages, "FileReader.execute").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForScala(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Scala: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-scala#specifying-return-column-names-and-types
		name := "filter_by_role"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
			import com.snowflake.snowpark.functions._
			import com.snowflake.snowpark._
			object Filter {
				def filterByRole(session: Session, tableName: String, role: String): DataFrame = {
					val table = session.table(tableName)
					val filteredRows = table.filter(col("role") === role)
					return filteredRows
				}
			}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("table_name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForScalaProcedureRequest(id.SchemaObjectId(), *returns, "2.12", packages, "Filter.filterByRole").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForScala(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Python: returns result data type", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-python#running-concurrent-tasks-with-worker-processes
		name := "joblib_multiprocessing_proc"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeInt)

		definition := `
import joblib
from math import sqrt
def joblib_multiprocessing(session, i):
	result = joblib.Parallel(n_jobs=-1)(joblib.delayed(sqrt)(i ** 2) for i in range(10))
	return str(result)`

		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeString)
		returns := sdk.NewProcedureReturnsRequest().WithResultDataType(*dt)
		argument := sdk.NewProcedureArgumentRequest("i", nil).WithArgDataTypeOld(sdk.DataTypeInt)
		packages := []sdk.ProcedurePackageRequest{
			*sdk.NewProcedurePackageRequest("snowflake-snowpark-python"),
			*sdk.NewProcedurePackageRequest("joblib"),
		}
		request := sdk.NewCreateForPythonProcedureRequest(id.SchemaObjectId(), *returns, "3.8", packages, "joblib_multiprocessing").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForPython(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for Python: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-python#specifying-return-column-names-and-types
		name := "filterByRole"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
from snowflake.snowpark.functions import col
def filter_by_role(session, table_name, role):
	df = session.table(table_name)
	return df.filter(col("role") == role)`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("table_name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("snowflake-snowpark-python")}
		request := sdk.NewCreateForPythonProcedureRequest(id.SchemaObjectId(), *returns, "3.8", packages, "filter_by_role").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForPython(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for SQL: returns result data type", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-snowflake-scripting
		name := "output_message"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR)

		definition := `
		BEGIN
			RETURN message;
		END;`

		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureSQLReturnsRequest().WithResultDataType(*dt).WithNotNull(true)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithOrReplace(true).
			// Suddenly this is erroring out, when it used to not have an problem. Must be an error with the Snowflake API.
			// Created issue in docs-discuss channel. https://snowflake.slack.com/archives/C6380540P/p1707511734666249
			// Error:      	Received unexpected error:
			// 001003 (42000): SQL compilation error:
			// syntax error line 1 at position 210 unexpected 'NULL'.
			// syntax error line 1 at position 215 unexpected 'ON'.
			// WithNullInputBehavior(sdk.NullInputBehaviorPointer(sdk.NullInputBehaviorReturnNullInput)).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument})
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})

	t.Run("create procedure for SQL: returns table", func(t *testing.T) {
		name := "find_invoice_by_id"
		id := testClientHelper().Ids.NewSchemaObjectIdentifierWithArguments(name, sdk.DataTypeVARCHAR)

		definition := `
		DECLARE
			res RESULTSET DEFAULT (SELECT * FROM invoices WHERE id = :id);
		BEGIN
			RETURN TABLE(res);
		END;`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld("INTEGER")
		column2 := sdk.NewProcedureColumnRequest("price", nil).WithColumnDataTypeOld("NUMBER(12,2)")
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2})
		returns := sdk.NewProcedureSQLReturnsRequest().WithTable(*returnsTable)
		argument := sdk.NewProcedureArgumentRequest("id", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithOrReplace(true).
			// SNOW-1051627 todo: uncomment once null input behavior working again
			// WithNullInputBehavior(sdk.NullInputBehaviorPointer(sdk.NullInputBehaviorReturnNullInput)).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument})
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(procedures), 1)
	})
}

func TestInt_OtherProcedureFunctions(t *testing.T) {
	client := testClient(t)
	ctx := testContext(t)

	assertProcedure := func(t *testing.T, id sdk.SchemaObjectIdentifierWithArguments, secure bool) {
		t.Helper()

		procedure, err := client.Procedures.ShowByID(ctx, id)
		require.NoError(t, err)

		assert.NotEmpty(t, procedure.CreatedOn)
		assert.Equal(t, id.Name(), procedure.Name)
		assert.Equal(t, false, procedure.IsBuiltin)
		assert.Equal(t, false, procedure.IsAggregate)
		assert.Equal(t, false, procedure.IsAnsi)
		assert.Equal(t, 1, procedure.MinNumArguments)
		assert.Equal(t, 1, procedure.MaxNumArguments)
		assert.NotEmpty(t, procedure.ArgumentsOld)
		assert.NotEmpty(t, procedure.ArgumentsRaw)
		assert.NotEmpty(t, procedure.Description)
		assert.NotEmpty(t, procedure.CatalogName)
		assert.Equal(t, false, procedure.IsTableFunction)
		assert.Equal(t, false, procedure.ValidForClustering)
		assert.Equal(t, secure, procedure.IsSecure)
	}

	cleanupProcedureHandle := func(id sdk.SchemaObjectIdentifierWithArguments) func() {
		return func() {
			err := client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id))
			if errors.Is(err, sdk.ErrObjectNotExistOrAuthorized) {
				return
			}
			require.NoError(t, err)
		}
	}

	createProcedureForSQLHandle := func(t *testing.T, cleanup bool) *sdk.Procedure {
		t.Helper()

		definition := `
	BEGIN
		RETURN message;
	END;`
		id := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeVARCHAR)
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureSQLReturnsRequest().WithResultDataType(*dt).WithNotNull(true)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithSecure(true).
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsCaller))
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)
		if cleanup {
			t.Cleanup(cleanupProcedureHandle(id))
		}
		procedure, err := client.Procedures.ShowByID(ctx, id)
		require.NoError(t, err)
		return procedure
	}

	t.Run("alter procedure: rename", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, false)

		id := f.ID()
		nid := testClientHelper().Ids.RandomSchemaObjectIdentifier()
		nidWithArguments := sdk.NewSchemaObjectIdentifierWithArguments(nid.DatabaseName(), nid.SchemaName(), nid.Name(), id.ArgumentDataTypes()...)

		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithRenameTo(nid))
		if err != nil {
			t.Cleanup(cleanupProcedureHandle(id))
		} else {
			t.Cleanup(cleanupProcedureHandle(nidWithArguments))
		}
		require.NoError(t, err)

		_, err = client.Procedures.ShowByID(ctx, id)
		assert.ErrorIs(t, err, collections.ErrObjectNotFound)

		e, err := client.Procedures.ShowByID(ctx, nidWithArguments)
		require.NoError(t, err)
		require.Equal(t, nid.Name(), e.Name)
	})

	t.Run("alter procedure: set log level", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)

		id := f.ID()
		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithSetLogLevel("DEBUG"))
		require.NoError(t, err)
		assertProcedure(t, id, true)
	})

	t.Run("alter procedure: set trace level", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)

		id := f.ID()
		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithSetTraceLevel("ALWAYS"))
		require.NoError(t, err)
		assertProcedure(t, id, true)
	})

	t.Run("alter procedure: set comment", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)

		id := f.ID()
		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithSetComment("comment"))
		require.NoError(t, err)
		assertProcedure(t, id, true)
	})

	t.Run("alter procedure: unset comment", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)

		id := f.ID()
		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithUnsetComment(true))
		require.NoError(t, err)
		assertProcedure(t, id, true)
	})

	t.Run("alter procedure: set execute as", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)

		id := f.ID()
		err := client.Procedures.Alter(ctx, sdk.NewAlterProcedureRequest(id).WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsOwner)))
		require.NoError(t, err)
		assertProcedure(t, id, true)
	})

	t.Run("show procedure for SQL: without like", func(t *testing.T) {
		f1 := createProcedureForSQLHandle(t, true)
		f2 := createProcedureForSQLHandle(t, true)

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest())
		require.NoError(t, err)

		require.GreaterOrEqual(t, len(procedures), 1)
		require.Contains(t, procedures, *f1)
		require.Contains(t, procedures, *f2)
	})

	t.Run("show procedure for SQL: with like", func(t *testing.T) {
		f1 := createProcedureForSQLHandle(t, true)
		f2 := createProcedureForSQLHandle(t, true)

		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest().WithLike(sdk.Like{Pattern: &f1.Name}))
		require.NoError(t, err)

		require.Equal(t, 1, len(procedures))
		require.Contains(t, procedures, *f1)
		require.NotContains(t, procedures, *f2)
	})

	t.Run("show procedure for SQL: no matches", func(t *testing.T) {
		procedures, err := client.Procedures.Show(ctx, sdk.NewShowProcedureRequest().WithLike(sdk.Like{Pattern: sdk.String("non-existing-id-pattern")}))
		require.NoError(t, err)
		require.Equal(t, 0, len(procedures))
	})

	t.Run("describe procedure for SQL", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)
		id := f.ID()

		details, err := client.Procedures.Describe(ctx, id)
		require.NoError(t, err)
		pairs := make(map[string]string)
		for _, detail := range details {
			pairs[detail.Property] = detail.Value
		}
		require.Equal(t, "SQL", pairs["language"])
		require.Equal(t, "CALLER", pairs["execute as"])
		require.Equal(t, "(MESSAGE VARCHAR)", pairs["signature"])
		require.Equal(t, "\n\tBEGIN\n\t\tRETURN message;\n\tEND;", pairs["body"])
	})

	t.Run("drop procedure for SQL", func(t *testing.T) {
		definition := `
		BEGIN
			RETURN message;
		END;`
		id := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeVARCHAR)
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureSQLReturnsRequest().WithResultDataType(*dt).WithNotNull(true)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsCaller))
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)

		err = client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id))
		require.NoError(t, err)
	})
}

func TestInt_CallProcedure(t *testing.T) {
	client := testClient(t)
	ctx := testContext(t)

	databaseId, schemaId := testClientHelper().Ids.DatabaseId(), testClientHelper().Ids.SchemaId()
	cleanupProcedureHandle := func(id sdk.SchemaObjectIdentifierWithArguments) func() {
		return func() {
			err := client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id))
			if errors.Is(err, sdk.ErrObjectNotExistOrAuthorized) {
				return
			}
			require.NoError(t, err)
		}
	}

	createTableHandle := func(t *testing.T, table sdk.SchemaObjectIdentifier) {
		t.Helper()

		_, err := client.ExecForTests(ctx, fmt.Sprintf(`CREATE OR REPLACE TABLE %s (id NUMBER, name VARCHAR, role VARCHAR)`, table.FullyQualifiedName()))
		require.NoError(t, err)
		_, err = client.ExecForTests(ctx, fmt.Sprintf(`INSERT INTO %s (id, name, role) VALUES (1, 'Alice', 'op'), (2, 'Bob', 'dev'), (3, 'Cindy', 'dev')`, table.FullyQualifiedName()))
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := client.ExecForTests(ctx, fmt.Sprintf(`DROP TABLE %s`, table.FullyQualifiedName()))
			require.NoError(t, err)
		})
	}

	// create a employees table
	tid := sdk.NewSchemaObjectIdentifier(databaseId.Name(), schemaId.Name(), "employees")
	createTableHandle(t, tid)

	createProcedureForSQLHandle := func(t *testing.T, cleanup bool) *sdk.Procedure {
		t.Helper()

		definition := `
		BEGIN
			RETURN message;
		END;`
		id := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeVARCHAR)
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureSQLReturnsRequest().WithResultDataType(*dt).WithNotNull(true)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithSecure(true).
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsCaller))
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)
		if cleanup {
			t.Cleanup(cleanupProcedureHandle(id))
		}
		procedure, err := client.Procedures.ShowByID(ctx, id)
		require.NoError(t, err)
		return procedure
	}

	t.Run("call procedure for SQL: argument positions", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)
		err := client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(f.ID().SchemaObjectId()).WithCallArguments([]string{"'hi'"}))
		require.NoError(t, err)
	})

	t.Run("call procedure for SQL: argument names", func(t *testing.T) {
		f := createProcedureForSQLHandle(t, true)
		err := client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(f.ID().SchemaObjectId()).WithCallArguments([]string{"message => 'hi'"}))
		require.NoError(t, err)
	})

	t.Run("call procedure for Java: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-java#omitting-return-column-names-and-types
		name := "filter_by_role"
		id := sdk.NewSchemaObjectIdentifierWithArguments(databaseId.Name(), schemaId.Name(), name, sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
		import com.snowflake.snowpark_java.*;
		public class Filter {
			public DataFrame filterByRole(Session session, String name, String role) {
				DataFrame table = session.table(name);
				DataFrame filteredRows = table.filter(Functions.col("role").equal_to(Functions.lit(role)));
				return filteredRows;
			}
		}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForJavaProcedureRequest(id.SchemaObjectId(), *returns, "11", packages, "Filter.filterByRole").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForJava(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		err = client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(id.SchemaObjectId()).WithCallArguments(ca))
		require.NoError(t, err)
	})

	t.Run("call procedure for Scala: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-scala#omitting-return-column-names-and-types
		name := "filter_by_role"
		id := sdk.NewSchemaObjectIdentifierWithArguments(databaseId.Name(), schemaId.Name(), name, sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
		import com.snowflake.snowpark.functions._
		import com.snowflake.snowpark._

		object Filter {
			def filterByRole(session: Session, name: String, role: String): DataFrame = {
				val table = session.table(name)
				val filteredRows = table.filter(col("role") === role)
				return filteredRows
			}
		}`
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		request := sdk.NewCreateForScalaProcedureRequest(id.SchemaObjectId(), *returns, "2.12", packages, "Filter.filterByRole").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForScala(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		err = client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(id.SchemaObjectId()).WithCallArguments(ca))
		require.NoError(t, err)
	})

	t.Run("call procedure for Javascript", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-javascript#basic-examples
		name := "stproc1"
		id := sdk.NewSchemaObjectIdentifierWithArguments(databaseId.Name(), schemaId.Name(), name, sdk.DataTypeFloat)

		definition := `
		var sql_command = "INSERT INTO stproc_test_table1 (num_col1) VALUES (" + FLOAT_PARAM1 + ")";
		try {
			snowflake.execute (
				{sqlText: sql_command}
			);
			return "Succeeded."; // Return a success/error indicator.
		}
		catch (err)  {
			return "Failed: " + err; // Return a success/error indicator.
		}`
		arg := sdk.NewProcedureArgumentRequest("FLOAT_PARAM1", nil).WithArgDataTypeOld(sdk.DataTypeFloat)
		request := sdk.NewCreateForJavaScriptProcedureRequest(id.SchemaObjectId(), nil, definition).
			WithResultDataTypeOld(sdk.DataTypeString).
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg}).
			WithNullInputBehavior(*sdk.NullInputBehaviorPointer(sdk.NullInputBehaviorStrict)).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsOwner))
		err := client.Procedures.CreateForJavaScript(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		err = client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(id.SchemaObjectId()).WithCallArguments([]string{"5.14::FLOAT"}))
		require.NoError(t, err)
	})

	t.Run("call procedure for Javascript: no arguments", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-javascript#basic-examples
		name := "sp_pi"
		id := sdk.NewSchemaObjectIdentifierWithArguments(databaseId.Name(), schemaId.Name(), name)

		definition := `return 3.1415926;`
		request := sdk.NewCreateForJavaScriptProcedureRequest(id.SchemaObjectId(), nil, definition).WithResultDataTypeOld(sdk.DataTypeFloat).WithNotNull(true).WithOrReplace(true)
		err := client.Procedures.CreateForJavaScript(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		err = client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(id.SchemaObjectId()))
		require.NoError(t, err)
	})

	t.Run("call procedure for Python: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-python#omitting-return-column-names-and-types
		id := sdk.NewSchemaObjectIdentifierWithArguments(databaseId.Name(), schemaId.Name(), "filterByRole", sdk.DataTypeVARCHAR, sdk.DataTypeVARCHAR)

		definition := `
from snowflake.snowpark.functions import col
def filter_by_role(session, name, role):
	df = session.table(name)
	return df.filter(col("role") == role)`
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("snowflake-snowpark-python")}
		request := sdk.NewCreateForPythonProcedureRequest(id.SchemaObjectId(), *returns, "3.8", packages, "filter_by_role").
			WithOrReplace(true).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition)
		err := client.Procedures.CreateForPython(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))

		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		err = client.Procedures.Call(ctx, sdk.NewCallProcedureRequest(id.SchemaObjectId()).WithCallArguments(ca))
		require.NoError(t, err)
	})
}

func TestInt_CreateAndCallProcedures(t *testing.T) {
	client := testClient(t)
	ctx := testContext(t)

	databaseId, schemaId := testClientHelper().Ids.DatabaseId(), testClientHelper().Ids.SchemaId()
	createTableHandle := func(t *testing.T, table sdk.SchemaObjectIdentifier) {
		t.Helper()

		_, err := client.ExecForTests(ctx, fmt.Sprintf(`CREATE OR REPLACE TABLE %s (id NUMBER, name VARCHAR, role VARCHAR)`, table.FullyQualifiedName()))
		require.NoError(t, err)
		_, err = client.ExecForTests(ctx, fmt.Sprintf(`INSERT INTO %s (id, name, role) VALUES (1, 'Alice', 'op'), (2, 'Bob', 'dev'), (3, 'Cindy', 'dev')`, table.FullyQualifiedName()))
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := client.ExecForTests(ctx, fmt.Sprintf(`DROP TABLE %s`, table.FullyQualifiedName()))
			require.NoError(t, err)
		})
	}

	// create a employees table
	tid := sdk.NewSchemaObjectIdentifier(databaseId.Name(), schemaId.Name(), "employees")
	createTableHandle(t, tid)

	t.Run("create and call procedure for Java: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-java#omitting-return-column-names-and-types
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("filter_by_role")

		definition := `
		import com.snowflake.snowpark_java.*;
		public class Filter {
			public DataFrame filterByRole(Session session, String name, String role) {
				DataFrame table = session.table(name);
				DataFrame filteredRows = table.filter(Functions.col("role").equal_to(Functions.lit(role)));
				return filteredRows;
			}
		}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		request := sdk.NewCreateAndCallForJavaProcedureRequest(name, *returns, "11", packages, "Filter.filterByRole", name).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition).
			WithCallArguments(ca)
		err := client.Procedures.CreateAndCallForJava(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for Scala: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-scala#omitting-return-column-names-and-types
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("filter_by_role")

		definition := `
		import com.snowflake.snowpark.functions._
		import com.snowflake.snowpark._

		object Filter {
			def filterByRole(session: Session, name: String, role: String): DataFrame = {
				val table = session.table(name)
				val filteredRows = table.filter(col("role") === role)
				return filteredRows
			}
		}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}
		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		request := sdk.NewCreateAndCallForScalaProcedureRequest(name, *returns, "2.12", packages, "Filter.filterByRole", name).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition).
			WithCallArguments(ca)
		err := client.Procedures.CreateAndCallForScala(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for Javascript", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-javascript#basic-examples
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("stproc1")

		definition := `
		var sql_command = "INSERT INTO stproc_test_table1 (num_col1) VALUES (" + FLOAT_PARAM1 + ")";
		try {
			snowflake.execute (
				{sqlText: sql_command}
			);
			return "Succeeded."; // Return a success/error indicator.
		}
		catch (err)  {
			return "Failed: " + err; // Return a success/error indicator.
		}`
		arg := sdk.NewProcedureArgumentRequest("FLOAT_PARAM1", nil).WithArgDataTypeOld(sdk.DataTypeFloat)
		request := sdk.NewCreateAndCallForJavaScriptProcedureRequest(name, nil, definition, name).
			WithResultDataTypeOld(sdk.DataTypeString).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg}).
			WithNullInputBehavior(*sdk.NullInputBehaviorPointer(sdk.NullInputBehaviorStrict)).
			WithCallArguments([]string{"5.14::FLOAT"})
		err := client.Procedures.CreateAndCallForJavaScript(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for Javascript: no arguments", func(t *testing.T) {
		// https://docs.snowflake.com/en/sql-reference/sql/create-procedure#examples
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("sp_pi")

		definition := `return 3.1415926;`
		request := sdk.NewCreateAndCallForJavaScriptProcedureRequest(name, nil, definition, name).WithResultDataTypeOld(sdk.DataTypeFloat).WithNotNull(true)
		err := client.Procedures.CreateAndCallForJavaScript(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for SQL: argument positions", func(t *testing.T) {
		definition := `
		BEGIN
			RETURN message;
		END;`

		name := testClientHelper().Ids.RandomAccountObjectIdentifier()
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureReturnsRequest().WithResultDataType(*dt)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateAndCallForSQLProcedureRequest(name, *returns, definition, name).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithCallArguments([]string{"message => 'hi'"})
		err := client.Procedures.CreateAndCallForSQL(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for Python: returns table", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-python#omitting-return-column-names-and-types
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("filterByRole")
		definition := `
from snowflake.snowpark.functions import col
def filter_by_role(session, name, role):
	df = session.table(name)
	return df.filter(col("role") == role)`
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("snowflake-snowpark-python")}
		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		request := sdk.NewCreateAndCallForPythonProcedureRequest(name, *returns, "3.8", packages, "filter_by_role", name).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition).
			WithCallArguments(ca)
		err := client.Procedures.CreateAndCallForPython(ctx, request)
		require.NoError(t, err)
	})

	t.Run("create and call procedure for Java: returns table and with clause", func(t *testing.T) {
		// https://docs.snowflake.com/en/developer-guide/stored-procedure/stored-procedures-java#omitting-return-column-names-and-types
		// TODO [SNOW-1348106]: make random with procedures rework
		name := sdk.NewAccountObjectIdentifier("filter_by_role")
		definition := `
		import com.snowflake.snowpark_java.*;
		public class Filter {
			public DataFrame filterByRole(Session session, String name, String role) {
				DataFrame table = session.table(name);
				DataFrame filteredRows = table.filter(Functions.col("role").equal_to(Functions.lit(role)));
				return filteredRows;
			}
		}`
		column1 := sdk.NewProcedureColumnRequest("id", nil).WithColumnDataTypeOld(sdk.DataTypeNumber)
		column2 := sdk.NewProcedureColumnRequest("name", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		column3 := sdk.NewProcedureColumnRequest("role", nil).WithColumnDataTypeOld(sdk.DataTypeVARCHAR)
		returnsTable := sdk.NewProcedureReturnsTableRequest().WithColumns([]sdk.ProcedureColumnRequest{*column1, *column2, *column3})
		returns := sdk.NewProcedureReturnsRequest().WithTable(*returnsTable)
		arg1 := sdk.NewProcedureArgumentRequest("name", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		arg2 := sdk.NewProcedureArgumentRequest("role", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("com.snowflake:snowpark:latest")}

		ca := []string{fmt.Sprintf(`'%s'`, tid.FullyQualifiedName()), "'dev'"}
		// TODO [SNOW-1348106]: make random with procedures rework
		cte := sdk.NewAccountObjectIdentifier("records")
		statement := fmt.Sprintf(`(SELECT name, role FROM %s WHERE name = 'Bob')`, tid.FullyQualifiedName())
		clause := sdk.NewProcedureWithClauseRequest(cte, statement).WithCteColumns([]string{"name", "role"})
		request := sdk.NewCreateAndCallForJavaProcedureRequest(name, *returns, "11", packages, "Filter.filterByRole", name).
			WithArguments([]sdk.ProcedureArgumentRequest{*arg1, *arg2}).
			WithProcedureDefinition(definition).
			WithWithClause(*clause).
			WithCallArguments(ca)
		err := client.Procedures.CreateAndCallForJava(ctx, request)
		require.NoError(t, err)
	})
}

func TestInt_ProceduresShowByID(t *testing.T) {
	client := testClient(t)
	ctx := testContext(t)

	cleanupProcedureHandle := func(id sdk.SchemaObjectIdentifierWithArguments) func() {
		return func() {
			err := client.Procedures.Drop(ctx, sdk.NewDropProcedureRequest(id))
			if errors.Is(err, sdk.ErrObjectNotExistOrAuthorized) {
				return
			}
			require.NoError(t, err)
		}
	}

	createProcedureForSQLHandle := func(t *testing.T, id sdk.SchemaObjectIdentifierWithArguments) {
		t.Helper()

		definition := `
	BEGIN
		RETURN message;
	END;`
		dt := sdk.NewProcedureReturnsResultDataTypeRequest(nil).WithResultDataTypeOld(sdk.DataTypeVARCHAR)
		returns := sdk.NewProcedureSQLReturnsRequest().WithResultDataType(*dt).WithNotNull(true)
		argument := sdk.NewProcedureArgumentRequest("message", nil).WithArgDataTypeOld(sdk.DataTypeVARCHAR)
		request := sdk.NewCreateForSQLProcedureRequest(id.SchemaObjectId(), *returns, definition).
			WithArguments([]sdk.ProcedureArgumentRequest{*argument}).
			WithExecuteAs(*sdk.ExecuteAsPointer(sdk.ExecuteAsCaller))
		err := client.Procedures.CreateForSQL(ctx, request)
		require.NoError(t, err)
		t.Cleanup(cleanupProcedureHandle(id))
	}

	t.Run("show by id - same name in different schemas", func(t *testing.T) {
		schema, schemaCleanup := testClientHelper().Schema.CreateSchema(t)
		t.Cleanup(schemaCleanup)

		id1 := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeVARCHAR)
		id2 := testClientHelper().Ids.NewSchemaObjectIdentifierWithArgumentsInSchema(id1.Name(), schema.ID(), sdk.DataTypeVARCHAR)

		createProcedureForSQLHandle(t, id1)
		createProcedureForSQLHandle(t, id2)

		e1, err := client.Procedures.ShowByID(ctx, id1)
		require.NoError(t, err)
		require.Equal(t, id1, e1.ID())

		e2, err := client.Procedures.ShowByID(ctx, id2)
		require.NoError(t, err)
		require.Equal(t, id2, e2.ID())
	})

	t.Run("show procedure by id - different name, same arguments", func(t *testing.T) {
		id1 := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeInt, sdk.DataTypeFloat, sdk.DataTypeVARCHAR)
		id2 := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(sdk.DataTypeInt, sdk.DataTypeFloat, sdk.DataTypeVARCHAR)
		e := testClientHelper().Procedure.CreateWithIdentifier(t, id1)
		testClientHelper().Procedure.CreateWithIdentifier(t, id2)

		es, err := client.Procedures.ShowByID(ctx, id1)
		require.NoError(t, err)
		require.Equal(t, *e, *es)
	})

	t.Run("show procedure by id - same name, different arguments", func(t *testing.T) {
		name := testClientHelper().Ids.Alpha()
		id1 := testClientHelper().Ids.NewSchemaObjectIdentifierWithArgumentsInSchema(name, testClientHelper().Ids.SchemaId(), sdk.DataTypeInt, sdk.DataTypeFloat, sdk.DataTypeVARCHAR)
		id2 := testClientHelper().Ids.NewSchemaObjectIdentifierWithArgumentsInSchema(name, testClientHelper().Ids.SchemaId(), sdk.DataTypeInt, sdk.DataTypeVARCHAR)
		e := testClientHelper().Procedure.CreateWithIdentifier(t, id1)
		testClientHelper().Procedure.CreateWithIdentifier(t, id2)

		es, err := client.Procedures.ShowByID(ctx, id1)
		require.NoError(t, err)
		require.Equal(t, *e, *es)
	})

	// This test shows behavior of detailed types (e.g. VARCHAR(20) and NUMBER(10, 0)) on Snowflake side for procedures.
	// For SHOW, data type is generalized both for argument and return type (to e.g. VARCHAR and NUMBER).
	// FOR DESCRIBE, data type is generalized for argument and works weirdly for the return type: type is generalized to the canonical one, but we also get the attributes.
	for _, tc := range []string{
		"NUMBER(36, 5)",
		"NUMBER(36)",
		"NUMBER",
		"DECIMAL",
		"INTEGER",
		"FLOAT",
		"DOUBLE",
		"VARCHAR",
		"VARCHAR(20)",
		"CHAR",
		"CHAR(10)",
		"TEXT",
		"BINARY",
		"BINARY(1000)",
		"VARBINARY",
		"BOOLEAN",
		"DATE",
		"DATETIME",
		"TIME",
		"TIMESTAMP_LTZ",
		"TIMESTAMP_NTZ",
		"TIMESTAMP_TZ",
		"VARIANT",
		"OBJECT",
		"ARRAY",
		"GEOGRAPHY",
		"GEOMETRY",
		"VECTOR(INT, 16)",
		"VECTOR(FLOAT, 8)",
	} {
		tc := tc
		t.Run(fmt.Sprintf("procedure returns non detailed data types of arguments for %s", tc), func(t *testing.T) {
			procName := "add"
			argName := "A"
			dataType, err := datatypes.ParseDataType(tc)
			require.NoError(t, err)
			args := []sdk.ProcedureArgumentRequest{
				*sdk.NewProcedureArgumentRequest(argName, dataType),
			}
			oldDataType := sdk.LegacyDataTypeFrom(dataType)
			idWithArguments := testClientHelper().Ids.RandomSchemaObjectIdentifierWithArguments(oldDataType)

			packages := []sdk.ProcedurePackageRequest{*sdk.NewProcedurePackageRequest("snowflake-snowpark-python")}
			definition := fmt.Sprintf("def add(%[1]s): %[1]s", argName)

			err = client.Procedures.CreateForPython(ctx, sdk.NewCreateForPythonProcedureRequest(
				idWithArguments.SchemaObjectId(),
				*sdk.NewProcedureReturnsRequest().WithResultDataType(*sdk.NewProcedureReturnsResultDataTypeRequest(dataType)),
				"3.8",
				packages,
				procName,
			).
				WithArguments(args).
				WithProcedureDefinition(definition),
			)
			require.NoError(t, err)

			procedure, err := client.Procedures.ShowByID(ctx, idWithArguments)
			require.NoError(t, err)
			assert.Equal(t, []sdk.DataType{oldDataType}, procedure.ArgumentsOld)
			assert.Equal(t, fmt.Sprintf("%[1]s(%[2]s) RETURN %[2]s", idWithArguments.Name(), oldDataType), procedure.ArgumentsRaw)

			details, err := client.Procedures.Describe(ctx, idWithArguments)
			require.NoError(t, err)
			pairs := make(map[string]string)
			for _, detail := range details {
				pairs[detail.Property] = detail.Value
			}
			assert.Equal(t, fmt.Sprintf("(%s %s)", argName, oldDataType), pairs["signature"])
			assert.Equal(t, dataType.Canonical(), pairs["returns"])
		})
	}
}
