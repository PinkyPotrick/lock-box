package com.lockbox.service.auditlog;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.AuditLog;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.AppConstants.EncryptionMessages;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link AuditLogServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link AuditLog} data for secure storage in the database. Uses AES-CBC encryption to secure sensitive log data.
 */
@Service
public class AuditLogServerEncryptionServiceImpl implements AuditLogServerEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(AuditLogServerEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive audit log data before storing in the database. Uses AES-CBC to encrypt sensitive fields.
     * 
     * @param auditLog - The audit log with plaintext data to be encrypted
     * @return {@link AuditLog} object with sensitive fields encrypted
     * @throws Exception If encryption fails
     */
    @Override
    public AuditLog encryptServerData(AuditLog auditLog) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            AuditLog encryptedAuditLog = new AuditLog();

            // Copy non-encrypted fields
            encryptedAuditLog.setId(auditLog.getId());
            encryptedAuditLog.setUser(auditLog.getUser());
            encryptedAuditLog.setTimestamp(auditLog.getTimestamp());
            encryptedAuditLog.setActionType(auditLog.getActionType());
            encryptedAuditLog.setOperationType(auditLog.getOperationType());
            encryptedAuditLog.setLogLevel(auditLog.getLogLevel());
            encryptedAuditLog.setActionStatus(auditLog.getActionStatus());
            encryptedAuditLog.setIpAddress(auditLog.getIpAddress());
            encryptedAuditLog.setClientInfo(auditLog.getClientInfo());
            encryptedAuditLog.setFailureReason(auditLog.getFailureReason());

            SecretKey aesKey = EncryptionUtils.generateAESKey();
            String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

            // Encrypt sensitive fields only
            if (auditLog.getResourceId() != null) {
                encryptedAuditLog.setResourceId(
                        genericEncryptionService.encryptStringWithAESCBC(auditLog.getResourceId(), aesKey));
            }

            if (auditLog.getResourceName() != null) {
                encryptedAuditLog.setResourceName(
                        genericEncryptionService.encryptStringWithAESCBC(auditLog.getResourceName(), aesKey));
            }

            if (auditLog.getAdditionalInfo() != null) {
                encryptedAuditLog.setAdditionalInfo(
                        genericEncryptionService.encryptStringWithAESCBC(auditLog.getAdditionalInfo(), aesKey));
            }

            encryptedAuditLog.setAesKey(rsaKeyPairService
                    .encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey), serverPublicKeyPem));

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Audit log server encryption process completed in {} ms", duration);

            return encryptedAuditLog;
        } catch (Exception e) {
            logger.error(EncryptionMessages.ENCRYPTION_ERROR, e.getMessage(), e);
            throw new Exception("Error encrypting audit log data", e);
        }
    }

    /**
     * Decrypts encrypted audit log data after retrieving from the database. Uses AES-CBC to decrypt sensitive fields.
     * 
     * @param auditLog - The audit log with encrypted data to be decrypted
     * @return {@link AuditLog} object with decrypted sensitive fields
     * @throws Exception If decryption fails
     */
    @Override
    public AuditLog decryptServerData(AuditLog auditLog) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            AuditLog decryptedAuditLog = new AuditLog();

            // Decrypt the audit log AES key used to encrypt sensitive fields
            String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(auditLog.getAesKey());
            SecretKey auditLogAesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

            // Copy non-encrypted fields
            decryptedAuditLog.setId(auditLog.getId());
            decryptedAuditLog.setUser(auditLog.getUser());
            decryptedAuditLog.setTimestamp(auditLog.getTimestamp());
            decryptedAuditLog.setActionType(auditLog.getActionType());
            decryptedAuditLog.setOperationType(auditLog.getOperationType());
            decryptedAuditLog.setLogLevel(auditLog.getLogLevel());
            decryptedAuditLog.setActionStatus(auditLog.getActionStatus());
            decryptedAuditLog.setIpAddress(auditLog.getIpAddress());
            decryptedAuditLog.setClientInfo(auditLog.getClientInfo());
            decryptedAuditLog.setFailureReason(auditLog.getFailureReason());

            // Decrypt sensitive fields only
            if (auditLog.getResourceId() != null) {
                decryptedAuditLog.setResourceId(
                        genericEncryptionService.decryptStringWithAESCBC(auditLog.getResourceId(), auditLogAesKey));
            }

            if (auditLog.getResourceName() != null) {
                decryptedAuditLog.setResourceName(
                        genericEncryptionService.decryptStringWithAESCBC(auditLog.getResourceName(), auditLogAesKey));
            }

            if (auditLog.getAdditionalInfo() != null) {
                decryptedAuditLog.setAdditionalInfo(
                        genericEncryptionService.decryptStringWithAESCBC(auditLog.getAdditionalInfo(), auditLogAesKey));
            }

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Audit log server decryption process completed in {} ms", duration);

            return decryptedAuditLog;
        } catch (Exception e) {
            logger.error(EncryptionMessages.DECRYPTION_ERROR, e.getMessage(), e);
            throw new Exception("Error decrypting audit log data", e);
        }
    }
}