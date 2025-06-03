package com.lockbox.utils;

import java.math.BigInteger;

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
   public static final String RSA_ECB_CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

   public static final int LOGIN_HISTORY_LIMIT = 10;

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

   // Error messages
   public static class Errors {
      public static final String PUBLIC_KEY_CANNOT_BE_EMPTY = "The public key cannot be empty";
      public static final String INVALID_CREDENTIALS = "Invalid credentials";
   }

   // User validation patterns
   public static class ValidationPatterns {
      public static final String USERNAME_PATTERN = "^[a-zA-Z0-9_]+$";
      public static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@(.+)$";
   }
}