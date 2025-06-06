package com.lockbox.utils;

import java.math.BigInteger;
import java.time.temporal.ChronoUnit;

public class AppConstants {

   // The blockchain constants
   public static final int DIFFICULTY = 1;
   public static final double MINER_REWARD = 1;

   // The group parameter N, a large prime number.
   public static final BigInteger N = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187", 16);

   // The group parameter g, a generator modulo N.
   public static final BigInteger g = BigInteger.valueOf(2);

   // Encryption/Decryption algorithm constants
   public static final String AES_CYPHER = "AES";
   public static final int AES_256 = 256;
   public static final String RSA_CYPHER = "RSA";
   public static final int RSA_2048 = 2048;
   public static final String AES_CBC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
   public static final String AES_ECB_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
   public static final String RSA_ECB_CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding"; // Pagination and history constants
   public static final int LOGIN_HISTORY_LIMIT = 10;
   public static final int DEFAULT_PAGE_SIZE = 100;
   public static final int DEFAULT_PAGE_NUMBER = 0;

   // Time constants
   public static final int DEFAULT_AUDIT_LOG_RETENTION_MONTHS = 3;
   public static final ChronoUnit AUDIT_LOG_RETENTION_UNIT = ChronoUnit.MONTHS; // Format patterns
   public static final String CREDENTIAL_NAME_FORMAT = "%s%s";
   public static final String CREDENTIAL_NAME_SEPARATOR = " - ";
   public static final String DEFAULT_CREDENTIAL_NAME = "Credential";
   public static final String ISO_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";
   // Boolean string constants
   public static final String BOOLEAN_TRUE = String.valueOf(Boolean.TRUE);
   public static final String BOOLEAN_FALSE = String.valueOf(Boolean.FALSE);

   // Sort field names
   public static class SortFields {
      public static final String UPDATED_AT = "updatedAt";
      public static final String CREATED_AT = "createdAt";
      public static final String NAME = "name";
      public static final String TIMESTAMP = "timestamp";
   }

   // Object type names for logging
   public static class ObjectTypes {
      public static final String CREDENTIAL = "Credential";
      public static final String VAULT = "Vault";
      public static final String DOMAIN = "Domain";
      public static final String USER = "User";
      public static final String AUDIT_LOG = "Audit log";
   }

   // Entity type constants for validation
   public static class EntityTypes {
      public static final String CREDENTIAL = "Credential";
      public static final String VAULT = "Vault";
      public static final String DOMAIN = "Domain";
      public static final String USER = "User";
      public static final String GENERIC = "Generic";
      public static final String AUDIT_LOG = "AuditLog";
   }

   // Field name constants for validation messages
   public static class FieldNames {
      // Common field names
      public static final String USERNAME = "Username";
      public static final String PASSWORD = "Password";
      public static final String EMAIL = "Email";
      public static final String NOTES = "Notes";
      public static final String CATEGORY = "Category";
      public static final String NAME = "Name";
      public static final String DESCRIPTION = "Description";
      public static final String URL = "URL";
      public static final String DOMAIN = "Domain";
      public static final String ENCRYPTION_KEY = "Encryption key";

      // ID field names
      public static final String DOMAIN_ID = "Domain ID";
      public static final String VAULT_ID = "Vault ID";
      public static final String USER_ID = "User ID";

      // Object names
      public static final String CREDENTIAL_REQUEST = "Credential request";
      public static final String CREDENTIAL_DATA = "Credential data";
      public static final String CREDENTIAL_UPDATE = "Credential update request";
      public static final String VAULT_REQUEST = "Vault request";
      public static final String VAULT_DATA = "Vault data";
      public static final String DOMAIN_REQUEST = "Domain request";
      public static final String DOMAIN_DATA = "Domain data";

      // Additional user-related fields
      public static final String SALT = "Salt";
      public static final String VERIFIER = "Verifier";
      public static final String USER_REGISTRATION = "User registration data";
      public static final String VAULT_UPDATE = "Vault update request";

      // Audit log field names
      public static final String AUDIT_LOG_DATA = "Audit log data";
      public static final String ACTION_TYPE = "Action type";
      public static final String ACTION_STATUS = "Action status";
      public static final String RESOURCE_ID = "Resource ID";
      public static final String RESOURCE_NAME = "Resource name";
      public static final String CLIENT_INFO = "Client information";
      public static final String IP_ADDRESS = "IP address";
      public static final String FAILURE_REASON = "Failure reason";
      public static final String ADDITIONAL_INFO = "Additional information";
   }

   // Max length constants for validation
   public static class MaxLengths {
      public static final int USERNAME = 255;
      public static final int PASSWORD = 255;
      public static final int EMAIL = 255;
      public static final int NOTES = 2000;
      public static final int CATEGORY = 100;
      public static final int NAME = 255;
      public static final int DESCRIPTION = 1000;
      public static final int URL = 2048;
      public static final int LOGO = 255;

      // Added AuditLog-related max lengths
      public static final int ACTION_TYPE = 50;
      public static final int ACTION_STATUS = 20;
      public static final int RESOURCE_ID = 255;
      public static final int RESOURCE_NAME = 255;
      public static final int CLIENT_INFO = 1024;
      public static final int IP_ADDRESS = 45;
      public static final int FAILURE_REASON = 1024;
      public static final int ADDITIONAL_INFO = 2048;
   }

   // Validation error messages
   public static class ValidationErrors {
      // Common validation errors
      public static final String REQUIRED_FIELD = "{0} is required";
      public static final String MAX_LENGTH = "{0} cannot exceed {1} characters";
      public static final String INVALID_FORMAT = "Invalid format for {0}";

      // Credential specific errors
      public static final String USERNAME_REQUIRED = "Username is required";
      public static final String PASSWORD_REQUIRED = "Password is required";
      public static final String ENCRYPTION_KEY_REQUIRED = "Encryption key is required";
      public static final String DOMAIN_ID_REQUIRED = "Domain ID is required";
      public static final String VAULT_ID_REQUIRED = "Vault ID is required";
      public static final String INVALID_CATEGORY = "Invalid category. Allowed categories are: {0}";
      public static final String NULL_REQUEST = "{0} cannot be null";
      public static final String UPDATE_AT_LEAST_ONE = "At least one field must be provided for update";

      // Vault specific errors
      public static final String VAULT_NAME_REQUIRED = "Vault name is required";

      // Domain specific errors
      public static final String DOMAIN_NAME_REQUIRED = "Domain name is required";
      public static final String DOMAIN_URL_REQUIRED = "Domain URL is required";

      // User specific errors
      public static final String INVALID_USERNAME_FORMAT = "Invalid username format. Use only letters, numbers, and underscores.";
      public static final String USERNAME_EXISTS = "Username already exists";
      public static final String INVALID_EMAIL_FORMAT = "Invalid email format.";
      public static final String EMAIL_EXISTS = "This email is already used.";
      public static final String SALT_REQUIRED = "Salt cannot be empty.";
      public static final String VERIFIER_REQUIRED = "Verifier cannot be empty.";

      // Generic user validation errors (prevent enumeration attacks)
      public static final String USER_ALREADY_EXISTS = "User registration failed. Please try with different credentials.";
      public static final String REGISTRATION_ERROR = "An error occurred during registration. Please try again later.";

      // Added audit log validation errors
      public static final String INVALID_DATE_FORMAT = "Invalid date format. Use ISO format (yyyy-MM-ddTHH:mm:ss)";
      public static final String INVALID_DATE_RANGE = "Start date cannot be after end date";
      public static final String INVALID_OPERATION_TYPE = "Invalid operation type. Valid values are: READ, WRITE, UPDATE, DELETE, ALL";
      public static final String INVALID_LOG_LEVEL = "Invalid log level. Valid values are: DEBUG, INFO, WARNING, ERROR, CRITICAL, ALL";
   }

   public static class SessionKeyAttributes {
      public static final String USER_PUBLIC_KEY = "userPublicKey";
      public static final String USER_PRIVATE_KEY = "userPrivateKey";
      public static final String USER_AES_KEY = "userAesKey";
   }

   // HTTP session constants
   public static class HttpSessionAttributes {
      // User authentication attributes
      public static final String CLIENT_PUBLIC_VALUE_A = "clientPublicValueA";
      public static final String SERVER_PUBLIC_VALUE_B = "serverPublicValueB";
      public static final String SERVER_PRIVATE_VALUE_B = "serverPrivateValueB";
      public static final String DERIVED_USERNAME = "derivedUsername";
      public static final String DERIVED_KEY = "derivedKey";
      public static final String CLIENT_PUBLIC_KEY = "clientPublicKey";

      // User password change attributes
      public static final String PASSWORD_CLIENT_PUBLIC_VALUE_A = "passwordClientPublicValueA";
      public static final String PASSWORD_SERVER_PUBLIC_VALUE_B = "passwordServerPublicValueB";
      public static final String PASSWORD_SERVER_PRIVATE_VALUE_B = "passwordServerPrivateValueB";
      public static final String PASSWORD_DERIVED_USERNAME = "passwordDerivedUsername";
      public static final String PASSWORD_USER_ID = "passwordUserId";
   }

   // Authentication error messages
   public static class AuthenticationErrors {
      public static final String EMPTY_PUBLIC_KEY = "The public key cannot be empty";
      public static final String INVALID_CREDENTIALS = "Invalid credentials";
      public static final String INVALID_CLIENT_VALUE_A = "Authentication failed: Invalid client value A.";
      public static final String INVALID_SESSION = "Session expired or invalid";
      public static final String INVALID_PROOF = "Proof verification failed. Authorization aborted!";
      public static final String TOO_MANY_REQUESTS = "Too many requests. Please try again later.";
   }

   // Status messages for audit log actions
   public static class ActionStatus {
      public static final String SUCCESS = "SUCCESS";
      public static final String FAILURE = "FAILURE";
   }

   // Error messages
   public static class Errors {
      public static final String PUBLIC_KEY_CANNOT_BE_EMPTY = "The public key cannot be empty";
      public static final String INVALID_CREDENTIALS = "Invalid credentials";
      public static final String ACCESS_DENIED = "Access denied";
      public static final String VAULT_NOT_FOUND = "Vault not found";
      public static final String CREDENTIAL_NOT_FOUND = "Credential not found";
      public static final String DOMAIN_NOT_FOUND = "Domain not found";
      public static final String USER_NOT_FOUND = "User not found";
      public static final String FETCH_VAULTS_FAILED = "Failed to fetch vaults";
      public static final String FETCH_CREDENTIALS_FAILED = "Failed to fetch credentials";
      public static final String FETCH_DOMAINS_FAILED = "Failed to fetch domains";
      public static final String FETCH_AUDIT_LOGS_FAILED = "Failed to fetch audit logs";
      public static final String CREATE_AUDIT_LOG_FAILED = "Failed to create audit log";
   }

   // User validation patterns
   public static class ValidationPatterns {
      public static final String USERNAME_PATTERN = "^[a-zA-Z0-9_]+$";
      public static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@(.+)$";
   }

   // Audit log constants
   public static class AuditLogMessages {
      // Success messages
      public static final String CREDENTIAL_VIEWED = "Credential viewed from vault: ";
      public static final String CREDENTIAL_CREATED = "Credential created in vault: ";
      public static final String CREDENTIAL_UPDATED = "Credential updated in vault: ";
      public static final String CREDENTIAL_DELETED = "Credential deleted from vault: ";
      public static final String VAULT_VIEWED = "Vault viewed";
      public static final String VAULT_CREATED = "Vault created";
      public static final String VAULT_UPDATED = "Vault updated";
      public static final String VAULT_DELETED = "Vault deleted";
      public static final String DOMAIN_VIEWED = "Domain viewed";
      public static final String DOMAIN_CREATED = "Domain created";
      public static final String DOMAIN_UPDATED = "Domain updated";
      public static final String DOMAIN_DELETED = "Domain deleted";
      public static final String USER_LOGGED_IN = "User logged in";
      public static final String USER_LOGGED_OUT = "User logged out";
      public static final String USER_REGISTERED = "User registered";
      public static final String PASSWORD_CHANGED = "Password changed";
      public static final String ADMIN_CLEANED_AUDIT_LOGS = "Admin deleted %d audit logs, retention: ";

      // Failure messages
      public static final String UNAUTHORIZED_ACCESS = "Attempted unauthorized access";
      public static final String FAILED_CREDENTIAL_VIEW = "Failed to view credential in vault: ";
      public static final String FAILED_CREDENTIAL_CREATE = "Failed to create credential in vault: ";
      public static final String FAILED_CREDENTIAL_UPDATE = "Failed to update credential in vault: ";
      public static final String FAILED_CREDENTIAL_DELETE = "Failed to delete credential from vault: ";
      public static final String FAILED_VAULT_VIEW = "Failed to view vault";
      public static final String FAILED_VAULT_CREATE = "Failed to create vault";
      public static final String FAILED_VAULT_UPDATE = "Failed to update vault";
      public static final String FAILED_VAULT_DELETE = "Failed to delete vault";
      public static final String FAILED_DOMAIN_VIEW = "Failed to view domain";
      public static final String FAILED_DOMAIN_CREATE = "Failed to create domain";
      public static final String FAILED_DOMAIN_UPDATE = "Failed to update domain";
      public static final String FAILED_DOMAIN_DELETE = "Failed to delete domain";
      public static final String FAILED_LOGIN = "Failed login attempt";
      public static final String FAILED_REGISTRATION = "Failed registration attempt";
      public static final String FAILED_PASSWORD_CHANGE = "Failed password change attempt";
      public static final String FAILED_CLEANUP = "Failed to clean up audit logs";
   }

   // Encryption log messages
   public static class EncryptionMessages {
      public static final String ENCRYPTING_RESOURCE_ID = "Encrypting audit log resource ID with AES-CBC";
      public static final String ENCRYPTING_RESOURCE_NAME = "Encrypting audit log resource name with AES-CBC";
      public static final String ENCRYPTING_ADDITIONAL_INFO = "Encrypting audit log additional info with AES-CBC";
      public static final String DECRYPTING_RESOURCE_ID = "Decrypting audit log resource ID with AES-CBC";
      public static final String DECRYPTING_RESOURCE_NAME = "Decrypting audit log resource name with AES-CBC";
      public static final String DECRYPTING_ADDITIONAL_INFO = "Decrypting audit log additional info with AES-CBC";
      public static final String ENCRYPTION_ERROR = "Error encrypting audit log data: {}";
      public static final String DECRYPTION_ERROR = "Error decrypting audit log data: {}";
      public static final String USER_KEYS_NOT_FOUND = "User keys not found in session";
   }

   // Logging messages
   public static class LogMessages {
      public static final String AUDIT_LOG_FAILED = "Failed to create audit log: {}";
      public static final String USER_OWNERSHIP_WARNING = "User {} attempted to access {} {} belonging to user {}";
      public static final String RESOURCE_NOT_FOUND = "{} not found with ID: {}";
      public static final String RESOURCE_NOT_IN_PARENT = "{} {} does not belong to {} {}";
      public static final String UNAUTHORIZED_ACCESS = "User {} attempted to access {} {} they don't own";
   }

   // Scheduler messages
   public static class SchedulerMessages {
      public static final String CLEANUP_START = "Starting scheduled audit log cleanup";
      public static final String CLEANUP_COMPLETE = "Scheduled audit log cleanup completed, deleted {} logs";
      public static final String CLEANUP_ERROR = "Error during scheduled audit log cleanup: {}";
   }
}