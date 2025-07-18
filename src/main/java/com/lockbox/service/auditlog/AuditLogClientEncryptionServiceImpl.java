package com.lockbox.service.auditlog;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogRequestDTO;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link AuditLogClientEncryptionService} interface. Provides methods for encrypting and
 * decrypting audit log data for secure transmission between client and server.
 */
@Service
public class AuditLogClientEncryptionServiceImpl implements AuditLogClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(AuditLogClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts an audit log DTO for client response. Uses AES encryption to secure the audit log data.
     * 
     * @param auditLogDTO - The audit log data to encrypt
     * @return Encrypted {@link AuditLogResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public AuditLogResponseDTO encryptAuditLogForClient(AuditLogDTO auditLogDTO) throws Exception {
        if (auditLogDTO == null) {
            return null;
        }

        // Generate a helper AES key
        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        AuditLogResponseDTO responseDTO = new AuditLogResponseDTO();

        // Set basic field values that don't need encryption
        responseDTO.setId(auditLogDTO.getId());
        responseDTO.setUserId(auditLogDTO.getUserId());
        responseDTO.setTimestamp(auditLogDTO.getTimestamp());
        responseDTO.setActionType(auditLogDTO.getActionType());
        responseDTO.setOperationType(auditLogDTO.getOperationType());
        responseDTO.setLogLevel(auditLogDTO.getLogLevel());
        responseDTO.setActionStatus(auditLogDTO.getActionStatus());
        responseDTO.setIpAddress(auditLogDTO.getIpAddress());
        responseDTO.setClientInfo(auditLogDTO.getClientInfo());
        responseDTO.setFailureReason(auditLogDTO.getFailureReason());

        // Encrypt fields that need encryption
        if (auditLogDTO.getResourceId() != null) {
            EncryptedDataAesCbc encryptedResourceId = genericEncryptionService
                    .encryptDTOWithAESCBC(auditLogDTO.getResourceId(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedResourceId(encryptedDataAesCbcMapper.toDto(encryptedResourceId));
        }

        if (auditLogDTO.getResourceName() != null) {
            EncryptedDataAesCbc encryptedResourceName = genericEncryptionService
                    .encryptDTOWithAESCBC(auditLogDTO.getResourceName(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedResourceName(encryptedDataAesCbcMapper.toDto(encryptedResourceName));
        }

        if (auditLogDTO.getAdditionalInfo() != null) {
            EncryptedDataAesCbc encryptedAdditionalInfo = genericEncryptionService
                    .encryptDTOWithAESCBC(auditLogDTO.getAdditionalInfo(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedAdditionalInfo(encryptedDataAesCbcMapper.toDto(encryptedAdditionalInfo));
        }

        // Set the helper AES key used for encryption
        responseDTO.setHelperAesKey(EncryptionUtils.getAESKeyString(aesKey));

        long endTime = System.currentTimeMillis();
        logger.info("Audit log client encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts a list of audit log DTOs for client response.
     * 
     * @param auditLogDTOs - The list of audit log data to encrypt
     * @return {@link AuditLogListResponseDTO} containing encrypted audit logs ready for transmission
     * @throws Exception If encryption fails
     */
    @Override
    public AuditLogListResponseDTO encryptAuditLogListForClient(List<AuditLogDTO> auditLogDTOs) throws Exception {
        if (auditLogDTOs == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        List<AuditLogResponseDTO> encryptedAuditLogs = new ArrayList<>();
        for (AuditLogDTO auditLogDTO : auditLogDTOs) {
            encryptedAuditLogs.add(encryptAuditLogForClient(auditLogDTO));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Audit log list client encryption process completed in {} ms", endTime - startTime);

        return new AuditLogListResponseDTO(encryptedAuditLogs, auditLogDTOs.size());
    }

    /**
     * Decrypts an audit log request DTO from the client.
     * 
     * @param requestDTO - The encrypted audit log request from client
     * @return Decrypted {@link AuditLogDTO}
     * @throws Exception If decryption fails
     */
    @Override
    public AuditLogDTO decryptAuditLogFromClient(AuditLogRequestDTO requestDTO) throws Exception {
        long startTime = System.currentTimeMillis();
        if (requestDTO == null || requestDTO.getHelperAesKey() == null) {
            return null;
        }

        AuditLogDTO auditLogDTO = new AuditLogDTO();

        // Copy non-encrypted fields
        auditLogDTO.setUserId(requestDTO.getUserId());
        auditLogDTO.setActionType(requestDTO.getActionType());
        auditLogDTO.setOperationType(requestDTO.getOperationType());
        auditLogDTO.setLogLevel(requestDTO.getLogLevel());
        auditLogDTO.setActionStatus(requestDTO.getActionStatus());
        auditLogDTO.setIpAddress(requestDTO.getIpAddress());
        auditLogDTO.setClientInfo(requestDTO.getClientInfo());
        auditLogDTO.setFailureReason(requestDTO.getFailureReason());

        // Decrypt encrypted fields
        if (requestDTO.getEncryptedResourceId() != null) {
            auditLogDTO.setResourceId(genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedResourceId(),
                    String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedResourceName() != null) {
            auditLogDTO.setResourceName(genericEncryptionService.decryptDTOWithAESCBC(
                    requestDTO.getEncryptedResourceName(), String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedAdditionalInfo() != null) {
            auditLogDTO.setAdditionalInfo(genericEncryptionService.decryptDTOWithAESCBC(
                    requestDTO.getEncryptedAdditionalInfo(), String.class, requestDTO.getHelperAesKey()));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Audit log client decryption process completed in {} ms", endTime - startTime);

        return auditLogDTO;
    }
}