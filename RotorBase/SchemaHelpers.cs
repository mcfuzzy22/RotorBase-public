using System;
using System.Threading;
using System.Threading.Tasks;
using MySqlConnector;

namespace RotorBase;

public static class SchemaHelpers
{
    public static async Task EnsureEngineFamilyColumnsAsync(MySqlConnection conn, CancellationToken ct)
    {
        static async Task<bool> ColumnExistsAsync(MySqlConnection connection, CancellationToken token, string column)
        {
            await using var check = new MySqlCommand("SHOW COLUMNS FROM EngineFamily LIKE @col", connection);
            check.Parameters.AddWithValue("@col", column);
            return await check.ExecuteScalarAsync(token) is not null;
        }

        static async Task TryExecuteAsync(MySqlConnection connection, CancellationToken token, string sql)
        {
            try
            {
                await using var cmd = new MySqlCommand(sql, connection);
                await cmd.ExecuteNonQueryAsync(token);
            }
            catch (MySqlException ex) when (ex.Number is 1060 or 1061 or 1067 or 1068 or 1091)
            {
                // Column/index already present; safe to ignore for idempotent upgrades.
            }
        }

        static Task EnsureEnumColumnAsync(MySqlConnection connection, CancellationToken token, string column, string addSql, string modifySql)
        {
            return EnsureColumnAsync(connection, token, column, addSql, modifySql);
        }

        static async Task EnsureColumnAsync(MySqlConnection connection, CancellationToken token, string column, string addSql, string? modifySql)
        {
            if (!await ColumnExistsAsync(connection, token, column))
            {
                await TryExecuteAsync(connection, token, addSql);
            }

            if (!string.IsNullOrWhiteSpace(modifySql))
            {
                await TryExecuteAsync(connection, token, modifySql!);
            }
        }

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "induction",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS induction ENUM('NA','Turbo','TwinTurboSeq','Supercharged') NULL AFTER hp_max",
            "ALTER TABLE EngineFamily MODIFY COLUMN induction ENUM('NA','Turbo','TwinTurboSeq','Supercharged') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "injection",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS injection ENUM('Carb','TBI','EFI') NULL AFTER induction",
            "ALTER TABLE EngineFamily MODIFY COLUMN injection ENUM('Carb','TBI','EFI') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "omp_type",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS omp_type ENUM('None','Mechanical','Electric') NULL AFTER injection",
            "ALTER TABLE EngineFamily MODIFY COLUMN omp_type ENUM('None','Mechanical','Electric') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "ignition_layout",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS ignition_layout ENUM('LeadingTrailing','CoilOnPlug','Distributor') NULL AFTER omp_type",
            "ALTER TABLE EngineFamily MODIFY COLUMN ignition_layout ENUM('LeadingTrailing','CoilOnPlug','Distributor') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "intake_arch",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS intake_arch ENUM('4-Port','6-Port','Bridge','Peripheral') NULL AFTER ignition_layout",
            "ALTER TABLE EngineFamily MODIFY COLUMN intake_arch ENUM('4-Port','6-Port','Bridge','Peripheral') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "port_family",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS port_family ENUM('Side','Peripheral','Mixed') NULL AFTER intake_arch",
            "ALTER TABLE EngineFamily MODIFY COLUMN port_family ENUM('Side','Peripheral','Mixed') NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "egt_sensors",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS egt_sensors TINYINT NULL AFTER port_family",
            "ALTER TABLE EngineFamily MODIFY COLUMN egt_sensors TINYINT NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "o2_sensors",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS o2_sensors TINYINT NULL AFTER egt_sensors",
            "ALTER TABLE EngineFamily MODIFY COLUMN o2_sensors TINYINT NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "ecu_type",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS ecu_type ENUM('OEM','Aftermarket','None') NULL AFTER o2_sensors",
            "ALTER TABLE EngineFamily MODIFY COLUMN ecu_type ENUM('OEM','Aftermarket','None') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "turbo_system",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS turbo_system ENUM('None','Single','SequentialTwin','ParallelTwin') NULL AFTER ecu_type",
            "ALTER TABLE EngineFamily MODIFY COLUMN turbo_system ENUM('None','Single','SequentialTwin','ParallelTwin') NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "intercooler",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS intercooler BOOLEAN NULL AFTER turbo_system",
            "ALTER TABLE EngineFamily MODIFY COLUMN intercooler BOOLEAN NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "apex_seal_thickness_mm",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS apex_seal_thickness_mm DECIMAL(5,2) NULL AFTER intercooler",
            "ALTER TABLE EngineFamily MODIFY COLUMN apex_seal_thickness_mm DECIMAL(5,2) NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "rotor_mass_g",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS rotor_mass_g INT NULL AFTER apex_seal_thickness_mm",
            "ALTER TABLE EngineFamily MODIFY COLUMN rotor_mass_g INT NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "housing_step",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS housing_step ENUM('Standard','RX8_RENESIS','Ceramic','Aftermarket_Coated') NULL AFTER rotor_mass_g",
            "ALTER TABLE EngineFamily MODIFY COLUMN housing_step ENUM('Standard','RX8_RENESIS','Ceramic','Aftermarket_Coated') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "exhaust_port_type",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS exhaust_port_type ENUM('Side','Peripheral') NULL AFTER housing_step",
            "ALTER TABLE EngineFamily MODIFY COLUMN exhaust_port_type ENUM('Side','Peripheral') NULL"
        );

        await EnsureEnumColumnAsync(
            conn,
            ct,
            "emissions_pkg",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS emissions_pkg ENUM('None','JDM','USDM','Euro') NULL AFTER exhaust_port_type",
            "ALTER TABLE EngineFamily MODIFY COLUMN emissions_pkg ENUM('None','JDM','USDM','Euro') NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "compression_min_psi",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS compression_min_psi INT NULL AFTER emissions_pkg",
            "ALTER TABLE EngineFamily MODIFY COLUMN compression_min_psi INT NULL"
        );

        await EnsureColumnAsync(
            conn,
            ct,
            "compression_max_psi",
            "ALTER TABLE EngineFamily ADD COLUMN IF NOT EXISTS compression_max_psi INT NULL AFTER compression_min_psi",
            "ALTER TABLE EngineFamily MODIFY COLUMN compression_max_psi INT NULL"
        );

        const string attrDefSql = """
            CREATE TABLE IF NOT EXISTS EngineAttributeDef (
                engine_attr_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                code           VARCHAR(80) NOT NULL,
                name           VARCHAR(160) NOT NULL,
                data_type      ENUM('int','decimal','bool','text') NOT NULL,
                unit           VARCHAR(32) NULL,
                UNIQUE KEY uq_engine_attr_code (code)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """;

        const string attrValSql = """
            CREATE TABLE IF NOT EXISTS EngineAttributeValue (
                engine_family_id BIGINT UNSIGNED NOT NULL,
                engine_attr_id   BIGINT UNSIGNED NOT NULL,
                val_int          BIGINT NULL,
                val_decimal      DECIMAL(18,6) NULL,
                val_bool         BOOLEAN NULL,
                val_text         VARCHAR(512) NULL,
                PRIMARY KEY (engine_family_id, engine_attr_id),
                CONSTRAINT fk_engine_attr_value_family FOREIGN KEY (engine_family_id)
                    REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT fk_engine_attr_value_def FOREIGN KEY (engine_attr_id)
                    REFERENCES EngineAttributeDef(engine_attr_id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """;

        await TryExecuteAsync(conn, ct, attrDefSql);
        await TryExecuteAsync(conn, ct, attrValSql);

        const string compatSql = """
            CREATE TABLE IF NOT EXISTS CompatibilityRule (
                rule_id     BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                scope       ENUM('engine','part') NOT NULL DEFAULT 'part',
                part_id     BIGINT UNSIGNED NULL,
                category_id BIGINT UNSIGNED NULL,
                expr_json   JSON NOT NULL,
                message     VARCHAR(255) NULL,
                active      BOOLEAN NOT NULL DEFAULT TRUE,
                INDEX ix_rule_part (part_id),
                INDEX ix_rule_category (category_id),
                CONSTRAINT fk_rule_part FOREIGN KEY (part_id)
                    REFERENCES Part(part_id) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT fk_rule_category FOREIGN KEY (category_id)
                    REFERENCES Category(category_id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """;

        try
        {
            await TryExecuteAsync(conn, ct, compatSql);
        }
        catch (MySqlException ex) when (ex.Number is 1005 or 1215)
        {
            // Happens if referenced tables are absent during bootstrap.
        }
    }

    public static async Task EnsureCategoryRequirementColumnsAsync(MySqlConnection conn, CancellationToken ct)
    {
        static async Task<bool> ColumnExistsAsync(MySqlConnection connection, CancellationToken token, string column)
        {
            await using var check = new MySqlCommand("SHOW COLUMNS FROM CategoryRequirement LIKE @col", connection);
            check.Parameters.AddWithValue("@col", column);
            return await check.ExecuteScalarAsync(token) is not null;
        }

        static async Task<string?> GetPrimaryKeySignatureAsync(MySqlConnection connection, CancellationToken token)
        {
            const string sql = """
                SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',')
                FROM information_schema.statistics
                WHERE table_schema = DATABASE()
                  AND table_name = 'CategoryRequirement'
                  AND index_name = 'PRIMARY'
            """;

            await using var cmd = new MySqlCommand(sql, connection);
            var result = await cmd.ExecuteScalarAsync(token);
            return result switch
            {
                null => null,
                DBNull => null,
                _ => Convert.ToString(result)
            };
        }

        static async Task TryExecuteAsync(MySqlConnection connection, CancellationToken token, string sql)
        {
            try
            {
                await using var cmd = new MySqlCommand(sql, connection);
                await cmd.ExecuteNonQueryAsync(token);
            }
            catch (MySqlException ex) when (ex.Number is 1060 or 1061 or 1067 or 1068 or 1091)
            {
                // Column already exists / key exists / can't drop - safe to ignore for idempotent migrations.
            }
        }

        // Ensure req_id surrogate key and drop legacy composite primary key when present.
        var pkSignature = await GetPrimaryKeySignatureAsync(conn, ct);
        // Ensure supporting indexes exist before altering keys.
        await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD INDEX ix_req_engine_family (engine_family_id)");

        if (!string.Equals(pkSignature, "req_id", StringComparison.OrdinalIgnoreCase))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement DROP PRIMARY KEY");
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN req_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST");
        }
        else
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement MODIFY COLUMN req_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT");
        }

        await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement MODIFY COLUMN tree_id BIGINT UNSIGNED NULL");

        if (!await ColumnExistsAsync(conn, ct, "tree_scope"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN tree_scope BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER tree_id");
        }

        await TryExecuteAsync(conn, ct, "UPDATE CategoryRequirement SET tree_scope = IFNULL(tree_id, 0) WHERE tree_scope <> IFNULL(tree_id, 0)");

        await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD UNIQUE INDEX uq_category_requirement_scope (engine_family_id, category_id, tree_scope)");

        if (!await ColumnExistsAsync(conn, ct, "req_mode"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN req_mode ENUM('exact_count','min_count','structured','formula') NOT NULL DEFAULT 'exact_count' AFTER requirement_type");
            await TryExecuteAsync(conn, ct, "UPDATE CategoryRequirement SET req_mode = requirement_type WHERE req_mode IS NULL OR req_mode = ''");
        }
        else
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement MODIFY COLUMN req_mode ENUM('exact_count','min_count','structured','formula') NOT NULL DEFAULT 'exact_count'");
        }

        await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement MODIFY COLUMN requirement_type ENUM('exact_count','min_count','structured','formula') NOT NULL DEFAULT 'exact_count'");

        if (!await ColumnExistsAsync(conn, ct, "multiplier"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN multiplier DECIMAL(12,3) NULL");
        }

        if (!await ColumnExistsAsync(conn, ct, "operand_field"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN operand_field VARCHAR(80) NULL");
        }

        const string operandWhitelist = "'rotor_count','hp_min','hp_max','primary_injector_cc','secondary_injector_cc','fuel_pressure_base','intake_port_area_mm2','exhaust_port_area_mm2'";
        await TryExecuteAsync(conn, ct, $"UPDATE CategoryRequirement SET operand_field = NULL WHERE operand_field IS NOT NULL AND operand_field NOT IN ({operandWhitelist})");
        await TryExecuteAsync(conn, ct, $"ALTER TABLE CategoryRequirement MODIFY COLUMN operand_field ENUM({operandWhitelist}) NULL");

        if (!await ColumnExistsAsync(conn, ct, "round_mode"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN round_mode ENUM('none','ceil','floor','round') NOT NULL DEFAULT 'none'");
            await TryExecuteAsync(conn, ct, "UPDATE CategoryRequirement SET round_mode = 'none' WHERE round_mode IS NULL OR round_mode = ''");
        }
        else
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement MODIFY COLUMN round_mode ENUM('none','ceil','floor','round') NOT NULL DEFAULT 'none'");
        }

        if (!await ColumnExistsAsync(conn, ct, "notes"))
        {
            await TryExecuteAsync(conn, ct, "ALTER TABLE CategoryRequirement ADD COLUMN notes VARCHAR(255) NULL");
        }
    }
}
