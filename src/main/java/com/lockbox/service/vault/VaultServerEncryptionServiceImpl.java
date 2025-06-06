package com.lockbox.service.vault;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.Vault;
import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.AppConstants.EncryptionMessages;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link VaultServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link Vault} data for secure storage in the database. Uses AES-CBC encryption to secure sensitive vault data.
 */
@Service
public class VaultServerEncryptionServiceImpl implements VaultServerEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(VaultServerEncryptionServiceImpl.class);

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive vault data before storing in the database. Uses AES-CBC to encrypt sensitive fields.
     * 
     * @param vault - The vault with plaintext data to be encrypted
     * @return {@link Vault} object with sensitive fields encrypted
     * @throws Exception If encryption fails
     */
    @Override
    public Vault encryptServerData(Vault vault) throws Exception {
        try {
            // Get the user's public key from session
            String userPublicKeyPem = sessionKeyStore.getUserPublicKey();
            if (userPublicKeyPem == null) {
                throw new SecurityException("User public key not found in session");
            }

            Vault encryptedVault = new Vault();

            // Copy non-encrypted fields
            encryptedVault.setId(vault.getId());
            encryptedVault.setUser(vault.getUser());
            encryptedVault.setCreatedAt(vault.getCreatedAt());
            encryptedVault.setUpdatedAt(vault.getUpdatedAt());
            encryptedVault.setIcon(vault.getIcon());

            SecretKey aesKey = EncryptionUtils.generateAESKey();
            String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

            // Encrypt sensitive fields
            if (vault.getName() != null) {
                logger.debug("Encrypting vault name with AES-CBC");
                encryptedVault.setName(genericEncryptionService.encryptStringWithAESCBC(vault.getName(), aesKey));
            }

            if (vault.getDescription() != null) {
                logger.debug("Encrypting vault description with AES-CBC");
                encryptedVault.setDescription(
                        genericEncryptionService.encryptStringWithAESCBC(vault.getDescription(), aesKey));
            }

            encryptedVault.setAesKey(rsaKeyPairService.encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey),
                    serverPublicKeyPem));

            return encryptedVault;
        } catch (Exception e) {
            logger.error("Error encrypting vault data: {}", e.getMessage(), e);
            throw new Exception("Error encrypting vault data", e);
        }
    }

    /**
     * Decrypts encrypted vault data after retrieving from the database. Uses AES-CBC to decrypt sensitive fields.
     * 
     * @param vault - The vault with encrypted data to be decrypted
     * @return {@link Vault} object with decrypted sensitive fields
     * @throws Exception If decryption fails
     */
    @Override
    public Vault decryptServerData(Vault vault) throws Exception {
        try {
            // Get user's keys from session
            String userAesKey = sessionKeyStore.getUserAesKey();
            String userPrivateKey = sessionKeyStore.getUserPrivateKey();

            if (userAesKey == null || userPrivateKey == null) {
                throw new SecurityException(EncryptionMessages.USER_KEYS_NOT_FOUND);
            }

            Vault decryptedVault = new Vault();

            // Decrypt the vault AES key used to encrypt name and description
            String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(vault.getAesKey());
            SecretKey vaultAesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

            // Copy non-encrypted fields
            decryptedVault.setId(vault.getId());
            decryptedVault.setUser(vault.getUser());
            decryptedVault.setCreatedAt(vault.getCreatedAt());
            decryptedVault.setUpdatedAt(vault.getUpdatedAt());
            decryptedVault.setIcon(vault.getIcon());

            // Decrypt sensitive fields
            if (vault.getName() != null) {
                logger.debug("Decrypting vault name with AES-CBC");
                decryptedVault.setName(genericEncryptionService.decryptStringWithAESCBC(vault.getName(), vaultAesKey));
            }

            if (vault.getDescription() != null) {
                logger.debug("Decrypting vault description with AES-CBC");
                decryptedVault.setDescription(
                        genericEncryptionService.decryptStringWithAESCBC(vault.getDescription(), vaultAesKey));
            }

            return decryptedVault;
        } catch (Exception e) {
            logger.error("Error decrypting vault data: {}", e.getMessage(), e);
            throw new Exception("Error decrypting vault data", e);
        }
    }
}