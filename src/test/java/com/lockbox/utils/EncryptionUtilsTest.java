package com.lockbox.utils;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptionUtilsTest {

    @Test
    void testGenerateAESKey() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        assertNotNull(key);
        assertTrue(key.getEncoded().length > 0);
    }

    @Test
    void testGetAESKeyFromString() throws Exception {
        SecretKey originalKey = EncryptionUtils.generateAESKey();
        String keyString = EncryptionUtils.getAESKeyString(originalKey);
        SecretKey restoredKey = EncryptionUtils.getAESKeyFromString(keyString);
        assertArrayEquals(originalKey.getEncoded(), restoredKey.getEncoded());
    }

    @Test
    void testEncryptDecryptStringWithAESCBC() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        String originalText = "Hello, LockBox!";
        String encrypted = EncryptionUtils.encryptStringWithAESCBC(originalText, key);
        String decrypted = EncryptionUtils.decryptStringWithAESCBC(encrypted, key);
        assertEquals(originalText, decrypted);
    }

    @Test
    void testEncryptWithAESCBCAndDecryptWithAESCBC() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        String originalText = "LockBox is secure";
        var encryptedData = EncryptionUtils.encryptWithAESCBC(originalText, key);
        String decrypted = EncryptionUtils.decryptWithAESCBC(encryptedData.getEncryptedDataBase64(),
                encryptedData.getIvBase64(), encryptedData.getHmacBase64(), encryptedData.getAesKeyBase64());
        assertEquals(originalText, decrypted);
    }

    @Test
    void testDecryptUsername() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        String keyB64 = Base64.getEncoder().encodeToString(key.getEncoded());

        // Encrypt the username using AES-ECB manually
        String originalUsername = "testUser";
        byte[] encrypted;
        try {
            var cipher = javax.crypto.Cipher.getInstance(AppConstants.AES_ECB_CIPHER_ALGORITHM);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(originalUsername.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        String encryptedUsernameB64 = Base64.getEncoder().encodeToString(encrypted);

        // Decrypt using the method under test
        String decryptedUsername = EncryptionUtils.decryptUsername(encryptedUsernameB64, keyB64);
        assertEquals(originalUsername, decryptedUsername);
    }
}