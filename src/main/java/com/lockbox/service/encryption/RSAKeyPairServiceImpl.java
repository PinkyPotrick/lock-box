package com.lockbox.service.encryption;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.lockbox.utils.AppConstants;
import com.lockbox.utils.EncryptionUtils;

import jakarta.annotation.PostConstruct;

@Service
public class RSAKeyPairServiceImpl implements RSAKeyPairService {

    // Use property values from configuration
    @Value("${key.private.path:./config/server-private-key.pem}")
    private String privateKeyPath;

    @Value("${key.public.path:./config/server-public-key.pem}")
    private String publicKeyPath;

    // Define fallback directory for generating new keys if needed
    private static final String CONFIG_DIR = "./config";

    private KeyPair keyPair;

    @Override
    @PostConstruct
    public void init() {
        try {
            File privateKeyFile = new File(privateKeyPath);
            File publicKeyFile = new File(publicKeyPath);

            // Ensure the config directory exists
            Path configDir = Path.of(CONFIG_DIR);
            Files.createDirectories(configDir);

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                // Load the existing key pair from specified paths
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

    public String encryptRSAWithServerPublicKey(String decryptedData) {
        try {
            PublicKey publicKey = keyPair.getPublic();
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(decryptedData.getBytes());

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    @Override
    public String decryptRSAWithServerPrivateKey(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    @Override
    public String encryptRSAWithPublicKey(String decryptedData, String publicKeyPem) {
        try {
            // Remove PEM headers and footers, and strip out all non-base64 characters
            String publicKeyBase64 = publicKeyPem //
                    .replace("-----BEGIN PUBLIC KEY-----", "") //
                    .replace("-----END PUBLIC KEY-----", "") //
                    .replaceAll("\\s", "");

            // Decode the Base64 encoded public key
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);

            // Generate the PublicKey object from the byte array
            KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Initialize the cipher for encryption with the public key
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encrypt the data
            byte[] encryptedBytes = cipher.doFinal(decryptedData.getBytes());

            // Encode the encrypted data in Base64 and return it
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    @Override
    public String decryptRSAWithPrivateKey(String encryptedData, String privateKeyPem) {
        try {
            // Remove PEM headers and footers, and strip out all non-base64 characters
            String privateKeyBase64 = privateKeyPem //
                    .replace("-----BEGIN PRIVATE KEY-----", "") //
                    .replace("-----END PRIVATE KEY-----", "") //
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "") //
                    .replace("-----END RSA PRIVATE KEY-----", "") //
                    .replaceAll("\\s", "");

            // Decode the Base64 encoded private key
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

            // Determine if the key is in PKCS#1 or PKCS#8 format
            PrivateKey privateKey;
            KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
            if (privateKeyPem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
                // Convert PKCS#1 to PKCS#8
                privateKeyBytes = EncryptionUtils.convertPKCS1ToPKCS8(privateKeyBytes);
            }

            // Generate the PrivateKey object from the byte array
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            privateKey = keyFactory.generatePrivate(keySpec);

            // Initialize the cipher for decryption with the private key
            Cipher cipher = Cipher.getInstance(AppConstants.RSA_ECB_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decode the Base64 encoded encrypted data
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            // Decrypt the data
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    public KeyPair loadKeyPair() throws Exception {
        // Load public key
        String publicKeyPem = new String(Files.readAllBytes(Path.of(publicKeyPath)));
        PublicKey publicKey = loadPublicKey(publicKeyPem);

        // Load private key
        String privateKeyPem = new String(Files.readAllBytes(Path.of(privateKeyPath)));
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        return new KeyPair(publicKey, privateKey);
    }

    private PublicKey loadPublicKey(String publicKeyPem) throws Exception {
        // Remove PEM headers and footers, and strip out whitespace
        String publicKeyBase64 = publicKeyPem //
                .replace("-----BEGIN PUBLIC KEY-----", "") //
                .replace("-----END PUBLIC KEY-----", "") //
                .replaceAll("\\s", "");

        // Decode and create PublicKey
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey loadPrivateKey(String privateKeyPem) throws Exception {
        // Remove PEM headers and footers, and strip out whitespace
        String privateKeyBase64 = privateKeyPem //
                .replace("-----BEGIN PRIVATE KEY-----", "") //
                .replace("-----END PRIVATE KEY-----", "") //
                .replaceAll("\\s", "");

        // Decode and create PrivateKey
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(AppConstants.RSA_CYPHER);
        return keyFactory.generatePrivate(keySpec);
    }

    public void saveKeyPair(KeyPair keyPair) throws IOException {
        // Save the public key in PEM format
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" + //
                Base64.getMimeEncoder().encodeToString(publicKeySpec.getEncoded()) + //
                "\n-----END PUBLIC KEY-----";
        Files.write(Path.of(publicKeyPath), publicKeyPem.getBytes());

        // Save the private key in PEM format
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" + //
                Base64.getMimeEncoder().encodeToString(privateKeySpec.getEncoded()) + //
                "\n-----END PRIVATE KEY-----";
        Files.write(Path.of(privateKeyPath), privateKeyPem.getBytes());
    }
}
