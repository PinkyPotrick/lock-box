package com.lockbox.service;

import org.springframework.stereotype.Service;

import com.lockbox.utils.AppConstants;

import jakarta.annotation.PostConstruct;

import javax.crypto.Cipher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class RSAKeyPairServiceImpl implements RSAKeyPairService {

    // Define the directory and file paths
    private static final String CONFIG_DIR = "src/main/java/com/lockbox/config";
    private static final String PRIVATE_KEY_FILE = CONFIG_DIR + "/server-private-key.pem";
    private static final String PUBLIC_KEY_FILE = CONFIG_DIR + "/server-public-key.pem";
    
    private KeyPair keyPair;

    @Override
    @PostConstruct
    public void init() {
        try {
            // Ensure the config directory exists
            Files.createDirectories(Paths.get(CONFIG_DIR));

            if (new File(PRIVATE_KEY_FILE).exists() && new File(PUBLIC_KEY_FILE).exists()) {
                // Load the existing key pair
                this.keyPair = loadKeyPair();
            } else {
                // Generate a new key pair and save it
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AppConstants.RSA_CYPHER);
                keyPairGenerator.initialize(AppConstants.RSA_2048);
                this.keyPair = keyPairGenerator.generateKeyPair();
                saveKeyPair(this.keyPair);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error initializing RSA key pair", e);
        }
    }

    @Override
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    @Override
    public String getPublicKeyInPEM(PublicKey publicKey) {
        try {
            String publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            StringBuilder pemFormattedKey = new StringBuilder();
            pemFormattedKey.append("-----BEGIN PUBLIC KEY-----\n");
            pemFormattedKey.append(publicKeyEncoded.replaceAll("(.{64})", "$1\n"));
            pemFormattedKey.append("\n-----END PUBLIC KEY-----");

            return pemFormattedKey.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error converting public key to PEM format", e);
        }
    }

    @Override
    public String decryptRSAWithServerPrivateKey(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_CYPHER);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedBytes);
            
            // return Base64.getEncoder().encodeToString(decryptedBytes);  // Return as Base64 string for consistency
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    @Override
    public String encryptRSAWithPublicKey(String data, String publicKeyPem) {
        try {
            // Remove PEM headers and footers, and strip out all non-base64 characters
            String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("[^A-Za-z0-9+/=]", "");  // Keep only valid Base64 characters

            // Decode the Base64 encoded public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);

            // Generate the PublicKey object from the byte array
            KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Initialize the cipher for encryption with the public key
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_CYPHER);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encrypt the data
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());

            // Encode the encrypted data in Base64 and return it
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    private KeyPair loadKeyPair() throws Exception {
        // Load public key
        String publicKeyPem = new String(Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE)));
        PublicKey publicKey = loadPublicKey(publicKeyPem);

        // Load private key
        String privateKeyPem = new String(Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE)));
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        return new KeyPair(publicKey, privateKey);
    }

    private PublicKey loadPublicKey(String publicKeyPem) throws Exception {
        // Remove PEM headers and footers, and strip out whitespace
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        // Decode and create PublicKey
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey loadPrivateKey(String privateKeyPem) throws Exception {
        // Remove PEM headers and footers, and strip out whitespace
        String privateKeyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // Decode and create PrivateKey
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
        return keyFactory.generatePrivate(keySpec);
    }

    private void saveKeyPair(KeyPair keyPair) throws IOException {
        // Save the public key in PEM format
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                              Base64.getMimeEncoder().encodeToString(publicKeySpec.getEncoded()) +
                              "\n-----END PUBLIC KEY-----";
        Files.write(Paths.get(PUBLIC_KEY_FILE), publicKeyPem.getBytes());

        // Save the private key in PEM format
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                               Base64.getMimeEncoder().encodeToString(privateKeySpec.getEncoded()) +
                               "\n-----END PRIVATE KEY-----";
        Files.write(Paths.get(PRIVATE_KEY_FILE), privateKeyPem.getBytes());
    }
}
