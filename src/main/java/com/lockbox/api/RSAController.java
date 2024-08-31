package com.lockbox.api;

import org.springframework.web.bind.annotation.*;

import jakarta.annotation.PostConstruct;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

@RestController
@RequestMapping("/api/rsa-auth")
public class RSAController {

    private KeyPair keyPair;

    @PostConstruct
    public void init() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            this.keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error initializing RSA key pair", e);
        }
    }

    @GetMapping("/public-key")
    public String getPublicKey() {
        PublicKey publicKey = keyPair.getPublic();
        return convertToPem(publicKey);
        // return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    @PostMapping("/test-crypt")
    public ResponseEntity<String> decryptData(@RequestBody String encryptedData) {
        try {
            String decryptedData = decryptWithPrivateKey(encryptedData);
            return ResponseEntity.ok("Decrypted data: " + decryptedData);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Decryption failed: " + e.getMessage());
        }
    }

    private String decryptWithPrivateKey(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    private String convertToPem(PublicKey publicKey) {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        pem.append(encoded.replaceAll("(.{64})", "$1\n")); // Breaks the encoded key into 64-character lines
        pem.append("\n-----END PUBLIC KEY-----");
        return pem.toString();
    }
}
