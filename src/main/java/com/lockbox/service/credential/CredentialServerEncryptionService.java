package com.lockbox.service.credential;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.Credential;
import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

@Service
public class CredentialServerEncryptionService {

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts a credential object for storage in the database
     * 
     * @param credential The credential with plaintext data
     * @return A new credential with encrypted data
     * @throws Exception If encryption fails
     */
    public Credential encryptServerData(Credential credential) throws Exception {
        // Get the user's public key from session
        String userPublicKeyPem = sessionKeyStore.getUserPublicKey();
        if (userPublicKeyPem == null) {
            throw new SecurityException("User public key not found in session");
        }

        Credential encryptedCredential = new Credential();

        // Copy non-encrypted fields
        encryptedCredential.setId(credential.getId());
        encryptedCredential.setUserId(credential.getUserId());
        encryptedCredential.setDomainId(credential.getDomainId());
        encryptedCredential.setVaultId(credential.getVaultId());
        encryptedCredential.setCreatedAt(credential.getCreatedAt());
        encryptedCredential.setUpdatedAt(credential.getUpdatedAt());
        encryptedCredential.setLastUsed(credential.getLastUsed());

        // Encrypt sensitive fields
        if (credential.getUsername() != null) {
            encryptedCredential.setUsername(genericEncryptionService.encryptDTOWithRSA(credential.getUsername(),
                    String.class, userPublicKeyPem));
        }

        if (credential.getEmail() != null) {
            encryptedCredential.setEmail(
                    genericEncryptionService.encryptDTOWithRSA(credential.getEmail(), String.class, userPublicKeyPem));
        }

        if (credential.getPassword() != null) {
            encryptedCredential.setPassword(genericEncryptionService.encryptDTOWithRSA(credential.getPassword(),
                    String.class, userPublicKeyPem));
        }

        if (credential.getNotes() != null) {
            encryptedCredential.setNotes(
                    genericEncryptionService.encryptDTOWithRSA(credential.getNotes(), String.class, userPublicKeyPem));
        }

        if (credential.getCategory() != null) {
            encryptedCredential.setCategory(genericEncryptionService.encryptDTOWithRSA(credential.getCategory(),
                    String.class, userPublicKeyPem));
        }

        if (credential.getFavorite() != null) {
            encryptedCredential.setFavorite(genericEncryptionService.encryptDTOWithRSA(credential.getFavorite(),
                    String.class, userPublicKeyPem));
        }

        return encryptedCredential;
    }

    /**
     * Decrypts a credential object retrieved from the database
     * 
     * @param credential The credential with encrypted data
     * @return A new credential with decrypted data
     * @throws Exception If decryption fails
     */
    public Credential decryptServerData(Credential credential) throws Exception {
        // Get user's keys from session
        String userAesKey = sessionKeyStore.getUserAesKey();
        String userPrivateKey = sessionKeyStore.getUserPrivateKey();

        if (userAesKey == null || userPrivateKey == null) {
            throw new SecurityException("User keys not found in session");
        }

        Credential decryptedCredential = new Credential();
        String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(userAesKey);
        SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);
        String decryptedUserPrivateKey = genericEncryptionService.decryptStringWithAESCBC(userPrivateKey, aesKey);

        // Copy non-encrypted fields
        decryptedCredential.setId(credential.getId());
        decryptedCredential.setUserId(credential.getUserId());
        decryptedCredential.setDomainId(credential.getDomainId());
        decryptedCredential.setVaultId(credential.getVaultId());
        decryptedCredential.setCreatedAt(credential.getCreatedAt());
        decryptedCredential.setUpdatedAt(credential.getUpdatedAt());
        decryptedCredential.setLastUsed(credential.getLastUsed());

        // Decrypt sensitive fields
        if (credential.getUsername() != null) {
            decryptedCredential.setUsername(genericEncryptionService.decryptDTOWithRSA(credential.getUsername(),
                    String.class, decryptedUserPrivateKey));
        }

        if (credential.getEmail() != null) {
            decryptedCredential.setEmail(genericEncryptionService.decryptDTOWithRSA(credential.getEmail(), String.class,
                    decryptedUserPrivateKey));
        }

        if (credential.getPassword() != null) {
            decryptedCredential.setPassword(genericEncryptionService.decryptDTOWithRSA(credential.getPassword(),
                    String.class, decryptedUserPrivateKey));
        }

        if (credential.getNotes() != null) {
            decryptedCredential.setNotes(genericEncryptionService.decryptDTOWithRSA(credential.getNotes(), String.class,
                    decryptedUserPrivateKey));
        }

        if (credential.getCategory() != null) {
            decryptedCredential.setCategory(genericEncryptionService.decryptDTOWithRSA(credential.getCategory(),
                    String.class, decryptedUserPrivateKey));
        }

        if (credential.getFavorite() != null) {
            decryptedCredential.setFavorite(genericEncryptionService.decryptDTOWithRSA(credential.getFavorite(),
                    String.class, decryptedUserPrivateKey));
        }

        return decryptedCredential;
    }
}