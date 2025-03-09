package com.lockbox.service;

import com.lockbox.utils.AppConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;

class RSAKeyPairServiceImplTest {

    private RSAKeyPairServiceImpl service;
    private KeyPair ephemeralKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Generate an ephemeral in-memory key pair to avoid disk I/O
        ephemeralKeyPair = createEphemeralKeyPair();

        // Create a partial mock
        service = Mockito.spy(new RSAKeyPairServiceImpl());

        // Prevent the actual file-based init
        doNothing().when(service).init();

        // Stub loadKeyPair so it returns our in-memory key pair
        doReturn(ephemeralKeyPair).when(service).loadKeyPair();

        // Prevent the actual saving of key files
        doNothing().when(service).saveKeyPair(any(KeyPair.class));

        // Manually set the in-memory keyPair
        service.init(); // calls our doNothing() stub
        // or just set the field directly
        setKeyPairField(ephemeralKeyPair);
    }

    @Test
    void testKeysInMemory() {
        // Now the service should have our ephemeral key pair
        PublicKey pubKey = service.getPublicKey();
        PrivateKey privKey = service.getPrivateKey();
        assertNotNull(pubKey);
        assertNotNull(privKey);
    }

    @Test
    void testEncryptDecryptWithServerKeys() {
        String originalText = "Hello RSA";
        String encrypted = service.encryptRSAWithServerPublicKey(originalText);
        String decrypted = service.decryptRSAWithServerPrivateKey(encrypted);
        assertEquals(originalText, decrypted);
    }

    // Generate a temporary 2048-bit RSA key pair in memory
    private KeyPair createEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(AppConstants.RSA_CYPHER);
        kpg.initialize(AppConstants.RSA_2048);
        return kpg.generateKeyPair();
    }

    // Utility to directly set the private keyPair field
    private void setKeyPairField(KeyPair keyPair) {
        try {
            var field = RSAKeyPairServiceImpl.class.getDeclaredField("keyPair");
            field.setAccessible(true);
            field.set(service, keyPair);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}