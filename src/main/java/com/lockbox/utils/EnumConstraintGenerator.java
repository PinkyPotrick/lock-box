package com.lockbox.utils;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.NotificationPriority;
import com.lockbox.model.enums.NotificationStatus;
import com.lockbox.model.enums.NotificationType;
import com.lockbox.model.enums.OperationType;
import com.lockbox.model.enums.ResourceType;

public class EnumConstraintGenerator {

    public static void main(String[] args) throws Exception {
        // Map of enum classes to table/column mappings
        Map<Class<?>, String[]> enumMappings = new HashMap<>();

        // Add your enum classes and their corresponding table.column
        enumMappings.put(ActionType.class, new String[] { "audit_logs", "action_type" });
        enumMappings.put(OperationType.class, new String[] { "audit_logs", "operation_type" });
        enumMappings.put(LogLevel.class, new String[] { "audit_logs", "log_level" });
        enumMappings.put(NotificationType.class, new String[] { "notifications", "type" });
        enumMappings.put(NotificationPriority.class, new String[] { "notifications", "priority" });
        enumMappings.put(NotificationStatus.class, new String[] { "notifications", "status" });
        // Add ResourceType
        enumMappings.put(ResourceType.class, new String[] { "notifications", "resource_type" });

        // Create SQL script
        StringBuilder sql = new StringBuilder("-- Auto-generated SQL script for enum constraints\n");
        sql.append("BEGIN;\n\n");

        // Process each enum
        for (Map.Entry<Class<?>, String[]> entry : enumMappings.entrySet()) {
            Class<?> enumClass = entry.getKey();
            String table = entry.getValue()[0];
            String column = entry.getValue()[1];
            String constraintName = table + "_" + column + "_check";

            sql.append("-- Update constraint for " + enumClass.getSimpleName() + "\n");
            sql.append("ALTER TABLE " + table + " \n");
            sql.append("DROP CONSTRAINT IF EXISTS " + constraintName + ";\n\n");

            sql.append("ALTER TABLE " + table + "\n");
            sql.append("ADD CONSTRAINT " + constraintName + " \n");

            // Using character varying format to match existing ResourceType constraint
            sql.append("CHECK ((" + column + ")::text = ANY ((ARRAY[");

            // Get all enum values
            Object[] enumValues = enumClass.getEnumConstants();
            for (int i = 0; i < enumValues.length; i++) {
                sql.append("'" + enumValues[i].toString() + "'::character varying");
                if (i < enumValues.length - 1) {
                    sql.append(", ");
                }
            }

            sql.append("])::text[]));\n\n");
        }

        sql.append("COMMIT;\n");

        // Write to file
        Files.createDirectories(Paths.get("sql"));
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("sql/update_enum_constraints.sql"))) {
            writer.write(sql.toString());
        }

        System.out.println("SQL script generated at: sql/update_enum_constraints.sql");
    }
}