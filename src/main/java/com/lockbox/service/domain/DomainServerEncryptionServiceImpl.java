package com.lockbox.service.domain;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.Domain;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link DomainServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link Domain} data for secure storage in the database. Uses AES-CBC encryption to secure sensitive domain data.
 */
@Service
public class DomainServerEncryptionServiceImpl implements DomainServerEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(DomainServerEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive domain data before storing in the database. Uses AES-CBC to encrypt sensitive fields.
     * 
     * @param domain - The domain with plaintext data to be encrypted
     * @return {@link Domain} object with sensitive fields encrypted
     * @throws Exception If encryption fails
     */
    @Override
    public Domain encryptServerData(Domain domain) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Domain encryptedDomain = new Domain();

            // Copy non-encrypted fields
            encryptedDomain.setId(domain.getId());
            encryptedDomain.setUserId(domain.getUserId());
            encryptedDomain.setCreatedAt(domain.getCreatedAt());
            encryptedDomain.setUpdatedAt(domain.getUpdatedAt());
            encryptedDomain.setLogo(domain.getLogo());

            // Generate AES key for encrypting sensitive fields
            SecretKey aesKey = EncryptionUtils.generateAESKey();
            String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

            // Encrypt sensitive fields
            if (domain.getName() != null) {
                encryptedDomain.setName(genericEncryptionService.encryptStringWithAESCBC(domain.getName(), aesKey));
            }

            if (domain.getUrl() != null) {
                encryptedDomain.setUrl(genericEncryptionService.encryptStringWithAESCBC(domain.getUrl(), aesKey));
            }

            if (domain.getNotes() != null) {
                encryptedDomain.setNotes(genericEncryptionService.encryptStringWithAESCBC(domain.getNotes(), aesKey));
            }

            // Encrypt the AES key with RSA
            encryptedDomain.setAesKey(rsaKeyPairService.encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey),
                    serverPublicKeyPem));

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Domain server encryption process completed in {} ms", duration);

            return encryptedDomain;
        } catch (Exception e) {
            logger.error("Error encrypting domain data: {}", e.getMessage(), e);
            throw new Exception("Error encrypting domain data", e);
        }
    }

    /**
     * Decrypts encrypted domain data after retrieving from the database. Uses AES-CBC to decrypt sensitive fields.
     * 
     * @param domain - The domain with encrypted data to be decrypted
     * @return {@link Domain} object with decrypted sensitive fields
     * @throws Exception If decryption fails
     */
    @Override
    public Domain decryptServerData(Domain domain) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Domain decryptedDomain = new Domain();

            // Decrypt the domain AES key used to encrypt sensitive fields
            String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(domain.getAesKey());
            SecretKey domainAesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

            // Copy non-encrypted fields
            decryptedDomain.setId(domain.getId());
            decryptedDomain.setUserId(domain.getUserId());
            decryptedDomain.setCreatedAt(domain.getCreatedAt());
            decryptedDomain.setUpdatedAt(domain.getUpdatedAt());
            decryptedDomain.setLogo(domain.getLogo());

            // Decrypt sensitive fields
            if (domain.getName() != null) {
                decryptedDomain
                        .setName(genericEncryptionService.decryptStringWithAESCBC(domain.getName(), domainAesKey));
            }

            if (domain.getUrl() != null) {
                decryptedDomain.setUrl(genericEncryptionService.decryptStringWithAESCBC(domain.getUrl(), domainAesKey));
            }

            if (domain.getNotes() != null) {
                decryptedDomain
                        .setNotes(genericEncryptionService.decryptStringWithAESCBC(domain.getNotes(), domainAesKey));
            }

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Domain server decryption process completed in {} ms", duration);

            return decryptedDomain;
        } catch (Exception e) {
            logger.error("Error decrypting domain data: {}", e.getMessage(), e);
            throw new Exception("Error decrypting domain data", e);
        }
    }
}