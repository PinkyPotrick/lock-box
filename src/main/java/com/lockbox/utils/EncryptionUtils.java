package com.lockbox.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.lockbox.model.EncryptedDataAesCbc;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.DERNull;

public class EncryptionUtils {

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AppConstants.AES_CYPHER);
        keyGen.init(AppConstants.AES_256);
        SecretKey aesKey = keyGen.generateKey();
        return aesKey;
    }

    public static SecretKey getAESKeyFromString(String aesKeyString) {
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static String getAESKeyString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static String encryptStringWithAESCBC(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AppConstants.AES_CBC_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
        byte[] combinedData = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combinedData, 0, iv.length);
        System.arraycopy(encryptedData, 0, combinedData, iv.length, encryptedData.length);
        return Base64.getEncoder().encodeToString(combinedData);
    }

    public static String decryptStringWithAESCBC(String encryptedData, SecretKey secretKey) throws Exception {
        byte[] combinedData = Base64.getDecoder().decode(encryptedData);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[combinedData.length - iv.length];
        System.arraycopy(combinedData, 0, iv, 0, iv.length);
        System.arraycopy(combinedData, iv.length, encryptedBytes, 0, encryptedBytes.length);
        Cipher cipher = Cipher.getInstance(AppConstants.AES_CBC_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedData = cipher.doFinal(encryptedBytes);
        return new String(decryptedData, "UTF-8");
    }

    public static String decryptWithAESCBC(String encryptedData, String ivBase64, String hmacBase64,
            String aesKeyBase64) throws Exception {
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
        Cipher cipher = Cipher.getInstance(AppConstants.AES_CBC_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static EncryptedDataAesCbc encryptWithAESCBC(String data, SecretKey aesKey) throws Exception {
        byte[] aesKeyBytes = aesKey.getEncoded();

        // Generate a random IV
        byte[] ivBytes = new byte[16]; // 128-bit IV for AES
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);

        // Initialize the cipher for AES-CBC encryption
        Cipher cipher = Cipher.getInstance(AppConstants.AES_CBC_CIPHER_ALGORITHM);
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

    public static byte[] convertPKCS1ToPKCS8(byte[] pkcs1Bytes) throws Exception {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(pkcs1Bytes);
            ASN1InputStream asn1InputStream = new ASN1InputStream(bais)) {
            ASN1Primitive primitive = asn1InputStream.readObject();
            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(primitive);
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                    rsaPrivateKey);
            return privateKeyInfo.getEncoded();
        }
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
            Cipher cipher = Cipher.getInstance(AppConstants.AES_ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(decodedDerivedUsername);

            return new String(decryptedBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}
