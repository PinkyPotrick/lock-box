package com.lockbox.service.domain;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.model.Domain;
import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

@Component
public class DomainServerEncryptionService {

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    public Domain encryptServerData(Domain domain) throws Exception {
        // Get the user's public key from session
        String userPublicKeyPem = sessionKeyStore.getUserPublicKey();
        if (userPublicKeyPem == null) {
            throw new SecurityException("User public key not found in session. User might not be authenticated.");
        }

        Domain encryptedDomain = new Domain();

        // Copy non-encrypted fields
        encryptedDomain.setId(domain.getId());
        encryptedDomain.setUserId(domain.getUserId());
        encryptedDomain.setVaultId(domain.getVaultId());
        encryptedDomain.setLogo(domain.getLogo());
        encryptedDomain.setCreatedAt(domain.getCreatedAt());
        encryptedDomain.setUpdatedAt(domain.getUpdatedAt());

        // Encrypt user's sensitive data with the user's public key
        if (domain.getName() != null) {
            encryptedDomain.setName(
                    genericEncryptionService.encryptDTOWithRSA(domain.getName(), String.class, userPublicKeyPem));
        }

        if (domain.getUrl() != null) {
            encryptedDomain.setUrl(
                    genericEncryptionService.encryptDTOWithRSA(domain.getUrl(), String.class, userPublicKeyPem));
        }

        if (domain.getNotes() != null) {
            encryptedDomain.setNotes(
                    genericEncryptionService.encryptDTOWithRSA(domain.getNotes(), String.class, userPublicKeyPem));
        }

        return encryptedDomain;
    }

    public Domain decryptServerData(Domain domain) throws Exception {
        // Get the user's keys from session
        String userAesKey = sessionKeyStore.getUserAesKey();
        String userPrivateKey = sessionKeyStore.getUserPrivateKey();

        if (userAesKey == null || userPrivateKey == null) {
            throw new SecurityException("User keys not found in session. User might not be authenticated.");
        }

        Domain decryptedDomain = new Domain();
        String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(userAesKey);
        SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);
        String decryptedUserPrivateKey = genericEncryptionService.decryptStringWithAESCBC(userPrivateKey, aesKey);

        // Copy non-encrypted fields
        decryptedDomain.setId(domain.getId());
        decryptedDomain.setUserId(domain.getUserId());
        decryptedDomain.setVaultId(domain.getVaultId());
        decryptedDomain.setLogo(domain.getLogo());
        decryptedDomain.setCreatedAt(domain.getCreatedAt());
        decryptedDomain.setUpdatedAt(domain.getUpdatedAt());

        // Decrypt user's sensitive data with the user's private key
        if (domain.getName() != null) {
            decryptedDomain.setName(genericEncryptionService.decryptDTOWithRSA(domain.getName(), String.class,
                    decryptedUserPrivateKey));
        }

        if (domain.getUrl() != null) {
            decryptedDomain.setUrl(
                    genericEncryptionService.decryptDTOWithRSA(domain.getUrl(), String.class, decryptedUserPrivateKey));
        }

        if (domain.getNotes() != null) {
            decryptedDomain.setNotes(genericEncryptionService.decryptDTOWithRSA(domain.getNotes(), String.class,
                    decryptedUserPrivateKey));
        }

        return decryptedDomain;
    }
}
