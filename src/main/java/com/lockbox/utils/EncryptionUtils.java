package com.lockbox.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionUtils {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;  // 96-bit nonce/IV
    private static final int AES_KEY_SIZE = 256;

    private static final SecretKey SECRET_KEY;

    static {
        try {
            // For simplicity, using a static key. Ideally, this should be securely managed (e.g., in a vault)
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
            keyGen.init(AES_KEY_SIZE, new SecureRandom());
            SECRET_KEY = keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize encryption key", e);
        }
    }

    public static String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, parameterSpec);
            byte[] encryptedText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedTextWithIv = new byte[iv.length + encryptedText.length];
            System.arraycopy(iv, 0, encryptedTextWithIv, 0, iv.length);
            System.arraycopy(encryptedText, 0, encryptedTextWithIv, iv.length, encryptedText.length);
            return Base64.getEncoder().encodeToString(encryptedTextWithIv);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt data", e);
        }
    }

    public static String decrypt(String encryptedText) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(decodedBytes, 0, iv, 0, iv.length);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY, parameterSpec);
            byte[] originalText = cipher.doFinal(decodedBytes, iv.length, decodedBytes.length - iv.length);
            return new String(originalText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt data", e);
        }
    }
}
