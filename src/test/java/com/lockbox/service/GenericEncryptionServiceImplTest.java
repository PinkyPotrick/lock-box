package com.lockbox.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionServiceImpl;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;

class GenericEncryptionServiceImplTest {

    private GenericEncryptionServiceImpl service;
    private RSAKeyPairService rsaKeyPairService;

    @BeforeEach
    void setUp() {
        rsaKeyPairService = Mockito.mock(RSAKeyPairService.class);
        service = new GenericEncryptionServiceImpl();
        // Inject the mock into the service
        // (straightforward approach for testing)
        // Optionally use reflection or rewrite the service constructor for DI
        setField(service, "rsaKeyPairService", rsaKeyPairService);

    }

    @Test
    void testEncryptDecryptStringWithAESCBC() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        String original = "Hello LockBox";
        String encrypted = service.encryptStringWithAESCBC(original, key);
        String decrypted = service.decryptStringWithAESCBC(encrypted, key);

        assertEquals(original, decrypted);
    }

    @Test
    void testEncryptDecryptDTOWithAESCBC() throws Exception {
        SecretKey key = EncryptionUtils.generateAESKey();
        String original = "Sensitive info";
        EncryptedDataAesCbc encrypted = service.encryptDTOWithAESCBC(original, EncryptedDataAesCbc.class, key);
        String decrypted = service.decryptDTOWithAESCBC(encrypted, String.class, EncryptionUtils.getAESKeyString(key));
        assertEquals(original, decrypted);
    }

    @Test
    void testEncryptDecryptDTOWithRSA() throws Exception {
        // Mock RSA encryption/decryption
        when(rsaKeyPairService.encryptRSAWithServerPublicKey(anyString())).thenReturn("encrypted");
        when(rsaKeyPairService.decryptRSAWithServerPrivateKey("encrypted")).thenReturn("decrypted");
        String original = "RSA test";

        String encrypted = service.encryptDTOWithRSA(original, String.class);
        String decrypted = service.decryptDTOWithRSA(encrypted, String.class);

        assertEquals("encrypted", encrypted);
        assertEquals("decrypted", decrypted);
    }

    // Utility method to set a private field for this simple test scenario
    private static void setField(Object target, String fieldName, Object value) {
        try {
            var field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}