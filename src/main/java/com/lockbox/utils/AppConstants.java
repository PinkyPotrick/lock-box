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

     // HTTP session constants
     public static class HttpSessionAttributes {
        public static final String CLIENT_PUBLIC_VALUE_A = "clientPublicValueA";
        public static final String SERVER_PUBLIC_VALUE_B = "serverPublicValueB";
        public static final String SERVER_PRIVATE_VALUE_B = "serverPrivateValueB";
        public static final String DERIVED_USERNAME = "derivedUsername";
        public static final String CLIENT_PUBLIC_KEY = "clientPublicKey";
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
}
