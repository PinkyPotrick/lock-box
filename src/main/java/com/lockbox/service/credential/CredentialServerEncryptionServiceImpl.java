package com.lockbox.service.credential;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.Credential;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link CredentialServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link Credential} data for secure storage in the database. Uses AES-CBC encryption to secure sensitive credential
 * data.
 */
@Service
public class CredentialServerEncryptionServiceImpl implements CredentialServerEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(CredentialServerEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive credential data before storing in the database. Uses AES-CBC to encrypt sensitive fields.
     * 
     * @param credential - The credential with plaintext data to be encrypted
     * @return {@link Credential} object with sensitive fields encrypted
     * @throws Exception If encryption fails
     */
    @Override
    public Credential encryptServerData(Credential credential) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Credential encryptedCredential = new Credential();

            // Copy non-encrypted fields
            encryptedCredential.setId(credential.getId());
            encryptedCredential.setUserId(credential.getUserId());
            encryptedCredential.setVaultId(credential.getVaultId());
            encryptedCredential.setDomainId(credential.getDomainId());
            encryptedCredential.setCreatedAt(credential.getCreatedAt());
            encryptedCredential.setUpdatedAt(credential.getUpdatedAt());
            encryptedCredential.setLastUsed(credential.getLastUsed());

            // Generate AES key for encrypting sensitive data
            SecretKey aesKey = EncryptionUtils.generateAESKey();
            String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

            // Encrypt sensitive fields using AES-CBC
            if (credential.getUsername() != null) {
                encryptedCredential.setUsername(
                        genericEncryptionService.encryptStringWithAESCBC(credential.getUsername(), aesKey));
            }

            if (credential.getPassword() != null) {
                encryptedCredential.setPassword(
                        genericEncryptionService.encryptStringWithAESCBC(credential.getPassword(), aesKey));
            }

            if (credential.getEmail() != null) {
                encryptedCredential
                        .setEmail(genericEncryptionService.encryptStringWithAESCBC(credential.getEmail(), aesKey));
            }

            if (credential.getNotes() != null) {
                encryptedCredential
                        .setNotes(genericEncryptionService.encryptStringWithAESCBC(credential.getNotes(), aesKey));
            }

            if (credential.getCategory() != null) {
                encryptedCredential.setCategory(
                        genericEncryptionService.encryptStringWithAESCBC(credential.getCategory(), aesKey));
            }

            if (credential.getFavorite() != null) {
                encryptedCredential.setFavorite(
                        genericEncryptionService.encryptStringWithAESCBC(credential.getFavorite(), aesKey));
            }

            // Encrypt the AES key with RSA and store it
            encryptedCredential.setAesKey(rsaKeyPairService
                    .encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey), serverPublicKeyPem));

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Credential server encryption process completed in {} ms", duration);

            return encryptedCredential;
        } catch (Exception e) {
            logger.error("Error encrypting credential data: {}", e.getMessage(), e);
            throw new Exception("Error encrypting credential data", e);
        }
    }

    /**
     * Decrypts encrypted credential data after retrieving from the database. Uses AES-CBC to decrypt sensitive fields.
     * 
     * @param credential - The credential with encrypted data to be decrypted
     * @return {@link Credential} object with decrypted sensitive fields
     * @throws Exception If decryption fails
     */
    @Override
    public Credential decryptServerData(Credential credential) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Credential decryptedCredential = new Credential();

            // Decrypt the credential AES key used to encrypt sensitive fields
            String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(credential.getAesKey());
            SecretKey credentialAesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

            // Copy non-encrypted fields
            decryptedCredential.setId(credential.getId());
            decryptedCredential.setUserId(credential.getUserId());
            decryptedCredential.setVaultId(credential.getVaultId());
            decryptedCredential.setDomainId(credential.getDomainId());
            decryptedCredential.setCreatedAt(credential.getCreatedAt());
            decryptedCredential.setUpdatedAt(credential.getUpdatedAt());
            decryptedCredential.setLastUsed(credential.getLastUsed());

            // Decrypt sensitive fields using AES-CBC
            if (credential.getUsername() != null) {
                decryptedCredential.setUsername(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getUsername(), credentialAesKey));
            }

            if (credential.getPassword() != null) {
                decryptedCredential.setPassword(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getPassword(), credentialAesKey));
            }

            if (credential.getEmail() != null) {
                decryptedCredential.setEmail(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getEmail(), credentialAesKey));
            }

            if (credential.getNotes() != null) {
                decryptedCredential.setNotes(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getNotes(), credentialAesKey));
            }

            if (credential.getCategory() != null) {
                decryptedCredential.setCategory(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getCategory(), credentialAesKey));
            }

            if (credential.getFavorite() != null) {
                decryptedCredential.setFavorite(
                        genericEncryptionService.decryptStringWithAESCBC(credential.getFavorite(), credentialAesKey));
            }

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Credential server decryption process completed in {} ms", duration);

            return decryptedCredential;
        } catch (Exception e) {
            logger.error("Error decrypting credential data: {}", e.getMessage(), e);
            throw new Exception("Error decrypting credential data", e);
        }
    }
}