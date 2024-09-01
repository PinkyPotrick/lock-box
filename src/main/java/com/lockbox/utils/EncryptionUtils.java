package com.lockbox.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.lockbox.model.EncryptedDataAesCbc;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionUtils {

    public static String decryptWithAESCBC(String encryptedData, String ivBase64, String hmacBase64, String aesKeyBase64) throws Exception {
        // Decode the AES key, IV, encrypted data, and HMAC from Base64
        byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyBase64);
        byte[] ivBytes = Base64.getDecoder().decode(ivBase64);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] hmacReceivedBytes = Base64.getDecoder().decode(hmacBase64);

        // Verify HMAC for integrity
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec hmacKeySpec = new SecretKeySpec(aesKeyBytes, "HmacSHA256");
        hmac.init(hmacKeySpec);
        hmac.update(ivBytes);
        hmac.update(encryptedBytes);
        byte[] hmacCalculatedBytes = hmac.doFinal();

        if (!java.util.Arrays.equals(hmacCalculatedBytes, hmacReceivedBytes)) {
            throw new SecurityException("HMAC verification failed. Data integrity compromised.");
        }

        // Decrypt the data using AES-CBC
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static EncryptedDataAesCbc encryptWithAESCBC(String data) throws Exception {
        // Generate AES Key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();
        byte[] aesKeyBytes = aesKey.getEncoded();

        // Generate a random IV
        byte[] ivBytes = new byte[16]; // 128-bit IV for AES
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        // Initialize the cipher for AES-CBC encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

        // Encrypt the data
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Generate HMAC for integrity check
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec hmacKeySpec = new SecretKeySpec(aesKeyBytes, "HmacSHA256");
        hmac.init(hmacKeySpec);
        hmac.update(ivBytes);
        hmac.update(encryptedBytes);
        byte[] hmacBytes = hmac.doFinal();

        // Encode everything in Base64 and return as an array
        EncryptedDataAesCbc encryptedDataAesCbc = new EncryptedDataAesCbc();
        encryptedDataAesCbc.setEncryptedDataBase64(Base64.getEncoder().encodeToString(encryptedBytes));
        encryptedDataAesCbc.setIvBase64(Base64.getEncoder().encodeToString(ivBytes));
        encryptedDataAesCbc.setHmacBase64(Base64.getEncoder().encodeToString(hmacBytes));
        encryptedDataAesCbc.setAesKeyBase64(Base64.getEncoder().encodeToString(aesKeyBytes));

        return encryptedDataAesCbc;
    }

    // Method to decrypt the encrypted username using the derived key
    public static String decryptUsername(String derivedUsername, String derivedKey) {
        try {
            // Decode the Base64 encoded derived key
            byte[] decodedKey = Base64.getDecoder().decode(derivedKey);
            SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "AES");

            // Decode the Base64 encoded encrypted username
            byte[] decodedDerivedUsername = Base64.getDecoder().decode(derivedUsername);

            // AES encryption with ECB mode (deterministic)
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(decodedDerivedUsername);

            return new String(decryptedBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}
