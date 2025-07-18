package com.lockbox.service.credential;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lockbox.blockchain.service.BlockchainCredentialVerifier;
import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialMapper;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.model.Credential;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.service.security.SecurityMonitoringService;
import com.lockbox.service.vault.VaultService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.AuditLogMessages;
import com.lockbox.utils.AppConstants.Errors;
import com.lockbox.validators.CredentialValidator;

/**
 * Implementation of the {@link CredentialService} interface. Provides functionality for managing {@link Credential}
 * entities.
 */
@Service
public class CredentialServiceImpl implements CredentialService {

    private final Logger logger = LoggerFactory.getLogger(CredentialServiceImpl.class);

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private VaultService vaultService;

    @Autowired
    private CredentialServerEncryptionService credentialServerEncryptionService;

    @Autowired
    private CredentialClientEncryptionService credentialClientEncryptionService;

    @Autowired
    private CredentialValidator credentialValidator;

    @Autowired
    private CredentialMapper credentialMapper;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private NotificationCreationService notificationCreationService;

    @Autowired
    private SecurityMonitoringService securityMonitoringService;

    @Autowired(required = false)
    private BlockchainCredentialVerifier blockchainVerifier;

    @Value("${blockchain.feature.enabled:false}")
    private boolean blockchainFeatureEnabled;

    /**
     * Find all credentials for a specific vault with optional pagination.
     * 
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @param page    - Optional page number (0-based)
     * @param size    - Optional page size
     * @return {@link CredentialListResponseDTO} containing encrypted credentials
     * @throws Exception If vault not found, access denied, or retrieval fails
     */
    @Override
    public CredentialListResponseDTO findAllCredentialsByVault(String vaultId, String userId, Integer page,
            Integer size) throws Exception {
        // Verify vault ownership and get vault
        Optional<com.lockbox.model.Vault> vaultOpt = vaultService.findById(vaultId);
        if (!vaultOpt.isPresent() || !vaultOpt.get().getUser().getId().equals(userId)) {
            logger.warn("User {} attempted to access vault {} they don't own", userId, vaultId);
            throw new SecurityException(Errors.ACCESS_DENIED);
        }

        // Get vault name for response
        String vaultName = vaultOpt.get().getName();

        List<Credential> encryptedCredentials;
        int totalCount; // Handle pagination if specified
        if (page != null && size != null) {
            // Always sort by updatedAt DESC as standard approach
            Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
            Page<Credential> credentialPage = credentialRepository.findByVaultId(vaultId, pageable);
            encryptedCredentials = credentialPage.getContent();
            totalCount = (int) credentialRepository.countByVaultId(vaultId);
        } else {
            encryptedCredentials = credentialRepository.findByVaultId(vaultId);
            totalCount = encryptedCredentials.size();
        }

        List<Credential> decryptedCredentials = new ArrayList<>();

        // Decrypt each credential
        for (Credential encryptedCredential : encryptedCredentials) {
            decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
        }

        // Convert to DTOs
        List<CredentialDTO> credentialDTOs = credentialMapper.toDTOList(decryptedCredentials);

        // Encrypt for client response, including vault name and total count
        CredentialListResponseDTO response = credentialClientEncryptionService
                .encryptCredentialListForClient(credentialDTOs, vaultName);
        response.setTotalCount(totalCount);
        return response;
    }

    /**
     * Find a specific credential by ID.
     * 
     * @param id      - The credential ID
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @return {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or retrieval fails
     */
    @Override
    public CredentialResponseDTO findCredentialById(String id, String vaultId, String userId) throws Exception {
        try {
            // Find credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new Exception(Errors.CREDENTIAL_NOT_FOUND);
            }

            Credential encryptedCredential = credentialOpt.get();

            // Verify vault ownership
            if (!encryptedCredential.getVaultId().equals(vaultId)) {
                logger.warn("Credential {} does not belong to vault {}", id, vaultId);
                throw new Exception("Credential not found in specified vault");
            }

            // Verify user ownership
            if (!encryptedCredential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to access credential {} belonging to user {}", userId, id,
                        encryptedCredential.getUserId());
                throw new SecurityException("Access denied");
            }

            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);
            CredentialDTO credentialDTO = credentialMapper.toDTO(decryptedCredential);
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";

            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VIEW, OperationType.READ, LogLevel.INFO, id,
                        username, ActionStatus.SUCCESS, null,
                        String.format(AppConstants.AuditLogMessages.CREDENTIAL_VIEWED, vaultId));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            return credentialClientEncryptionService.encryptCredentialForClient(credentialDTO);
        } catch (Exception e) {
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VIEW, OperationType.READ, LogLevel.WARNING,
                        id, null, ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CREDENTIAL_VIEW + vaultId);
            } catch (Exception ex) {
                logger.error("Failed to create audit log: {}", ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Create a new credential.
     * 
     * @param requestDTO - The encrypted credential request DTO
     * @param vaultId    - The vault ID to add the credential to
     * @param userId     - The current user ID for authorization
     * @return Created {@link CredentialResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO createCredential(CredentialRequestDTO requestDTO, String vaultId, String userId)
            throws Exception {
        // First complete the existing credential creation logic
        CredentialResponseDTO responseDTO = createCredentialInternal(requestDTO, vaultId, userId);

        // Then add blockchain integration if enabled
        if (blockchainFeatureEnabled && blockchainVerifier != null) {
            try {
                // Find the saved credential and get its ID
                Optional<Credential> savedCredentialOpt = credentialRepository.findById(responseDTO.getId());

                if (savedCredentialOpt.isPresent()) {
                    Credential savedCredential = savedCredentialOpt.get();
                    Credential decryptedCredential = credentialServerEncryptionService
                            .decryptServerData(savedCredential);
                    CredentialDTO credentialDTO = credentialMapper.toDTO(decryptedCredential);

                    // Compute hash and store on blockchain asynchronously
                    String credentialHash = blockchainVerifier.computeCredentialHash(credentialDTO);
                    blockchainVerifier.storeCredentialHash(responseDTO.getId(), credentialHash).thenAccept(txHash -> {
                        logger.info("Credential hash stored on blockchain. TxHash: {}", txHash);
                    }).exceptionally(ex -> {
                        logger.error("Failed to store credential hash on blockchain: {}", ex.getMessage(), ex);
                        return null;
                    });
                }
            } catch (Exception e) {
                // Log error but don't fail the credential creation
                logger.error("Error while adding credential hash to blockchain: {}", e.getMessage(), e);
            }
        }

        return responseDTO;
    }

    /**
     * Internal method to handle credential creation without blockchain integration
     */
    private CredentialResponseDTO createCredentialInternal(CredentialRequestDTO requestDTO, String vaultId,
            String userId) throws Exception {
        try {
            // Validate the request
            credentialValidator.validateCredentialRequest(requestDTO);

            // Verify vault ownership - using vaultService
            if (!vaultService.isVaultOwnedByUser(vaultId, userId)) {
                logger.warn("User {} attempted to create credential in vault {} they don't own", userId, vaultId);
                throw new SecurityException("Access denied");
            }

            // Decrypt the request
            CredentialDTO credentialDTO = credentialClientEncryptionService.decryptCredentialFromClient(requestDTO);

            // Validate the decrypted data
            credentialValidator.validateCredentialDTO(credentialDTO);

            // Create entity from DTO
            Credential credential = credentialMapper.toEntity(credentialDTO);

            // Set vault, user, and timestamps
            credential.setVaultId(vaultId);
            credential.setUserId(userId);
            credential.setDomainId(credentialDTO.getDomainId());
            LocalDateTime now = LocalDateTime.now();
            credential.setCreatedAt(now);
            credential.setUpdatedAt(now);

            // Set favorite status
            credential.setFavorite(
                    credentialDTO.isFavorite() ? String.valueOf(Boolean.TRUE) : String.valueOf(Boolean.FALSE));

            // Encrypt and save
            Credential encryptedCredential = credentialServerEncryptionService.encryptServerData(credential);
            Credential savedCredential = credentialRepository.save(encryptedCredential);

            Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);
            CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);
            String username = decryptedSavedCredential.getUsername() != null ? decryptedSavedCredential.getUsername()
                    : "";

            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_CREATE, OperationType.WRITE, LogLevel.INFO,
                        savedCredential.getId(), username, ActionStatus.SUCCESS, null,
                        String.format(AuditLogMessages.CREDENTIAL_CREATED, vaultId));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
        } catch (Exception e) {
            CredentialDTO credentialDTO = credentialClientEncryptionService.decryptCredentialFromClient(requestDTO);
            String username = credentialDTO.getUsername() != null ? credentialDTO.getUsername() : "";

            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_CREATE, OperationType.WRITE, LogLevel.ERROR,
                        null, username, ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CREDENTIAL_CREATE + vaultId);
            } catch (Exception ex) {
                logger.error("Failed to create audit log: {}", ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Update an existing credential.
     * 
     * @param id         - The credential ID
     * @param requestDTO - The encrypted credential request DTO
     * @param vaultId    - The vault ID
     * @param userId     - The current user ID for authorization
     * @return Updated {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or update fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO updateCredential(String id, CredentialRequestDTO requestDTO, String vaultId,
            String userId) throws Exception {
        // First complete the existing credential update logic
        CredentialResponseDTO responseDTO = updateCredentialInternal(id, requestDTO, vaultId, userId);

        // Then add blockchain integration if enabled
        if (blockchainFeatureEnabled && blockchainVerifier != null) {
            try {
                // Find the updated credential
                Optional<Credential> updatedCredentialOpt = credentialRepository.findById(id);

                if (updatedCredentialOpt.isPresent()) {
                    Credential updatedCredential = updatedCredentialOpt.get();
                    Credential decryptedCredential = credentialServerEncryptionService
                            .decryptServerData(updatedCredential);
                    CredentialDTO credentialDTO = credentialMapper.toDTO(decryptedCredential);

                    // Compute hash and update on blockchain asynchronously
                    String credentialHash = blockchainVerifier.computeCredentialHash(credentialDTO);
                    blockchainVerifier.storeCredentialHash(id, credentialHash).thenAccept(txHash -> {
                        logger.info("Credential hash updated on blockchain. TxHash: {}", txHash);
                    }).exceptionally(ex -> {
                        logger.error("Failed to update credential hash on blockchain: {}", ex.getMessage(), ex);
                        return null;
                    });
                }
            } catch (Exception e) {
                // Log error but don't fail the credential update
                logger.error("Error while updating credential hash on blockchain: {}", e.getMessage(), e);
            }
        }

        return responseDTO;
    }

    /**
     * Internal method to handle credential updates without blockchain integration
     */
    private CredentialResponseDTO updateCredentialInternal(String id, CredentialRequestDTO requestDTO, String vaultId,
            String userId) throws Exception {
        try {
            // Validate the request
            credentialValidator.validateCredentialRequest(requestDTO);

            // Find credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new Exception("Credential not found");
            }

            Credential encryptedCredential = credentialOpt.get();

            // Verify vault ownership
            if (!encryptedCredential.getVaultId().equals(vaultId)) {
                logger.warn("Credential {} does not belong to vault {}", id, vaultId);
                throw new Exception("Credential not found in specified vault");
            }

            // Verify user ownership
            if (!encryptedCredential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to update credential {} belonging to user {}", userId, id,
                        encryptedCredential.getUserId());
                throw new SecurityException("Access denied");
            }

            // Decrypt the request
            CredentialDTO credentialDTO = credentialClientEncryptionService.decryptCredentialFromClient(requestDTO);

            // Validate the decrypted data
            credentialValidator.validateCredentialDTO(credentialDTO);

            // Decrypt existing credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);

            // Update fields
            if (credentialDTO.getUsername() != null) {
                decryptedCredential.setUsername(credentialDTO.getUsername());
            }

            if (credentialDTO.getEmail() != null) {
                decryptedCredential.setEmail(credentialDTO.getEmail());
            }

            if (credentialDTO.getPassword() != null) {
                decryptedCredential.setPassword(credentialDTO.getPassword());
            }

            if (credentialDTO.getNotes() != null) {
                decryptedCredential.setNotes(credentialDTO.getNotes());
            }

            if (credentialDTO.getCategory() != null) {
                decryptedCredential.setCategory(credentialDTO.getCategory());
            }

            if (credentialDTO.getDomainId() != null) {
                decryptedCredential.setDomainId(credentialDTO.getDomainId());
            }

            // Update favorite status if specified
            if (credentialDTO.getFavoriteSpecified()) {
                decryptedCredential.setFavorite(
                        credentialDTO.isFavorite() ? String.valueOf(Boolean.TRUE) : String.valueOf(Boolean.FALSE));
            }

            // Update timestamp
            decryptedCredential.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Credential encryptedUpdatedCredential = credentialServerEncryptionService
                    .encryptServerData(decryptedCredential);
            Credential savedCredential = credentialRepository.save(encryptedUpdatedCredential);

            // Decrypt for response
            Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and encrypt for client response
            CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);

            // Prepare a descriptive name for credential name
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";

            // Add audit logging before returning
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE, LogLevel.INFO,
                        id, username, ActionStatus.SUCCESS, null,
                        String.format(AuditLogMessages.CREDENTIAL_UPDATED, vaultId));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            // Get vault name for notification
            Optional<com.lockbox.model.Vault> vaultOpt = vaultService.findById(vaultId);
            String vaultName = "";
            if (vaultOpt.isPresent()) {
                vaultName = vaultOpt.get().getName();
            }

            // After successful update but before returning
            try {
                notificationCreationService.createCredentialUpdatedNotification(userId, username, vaultName, id,
                        vaultId);
            } catch (Exception e) {
                logger.error("Failed to create credential update notification: {}", e.getMessage());
            }

            // Add to updateCredential method:
            try {
                securityMonitoringService.monitorCredentialChanges(userId);
            } catch (Exception e) {
                logger.error("Error monitoring credential changes: {}", e.getMessage());
                // Don't fail the update if monitoring fails
            }

            return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
        } catch (Exception e) {
            // Add audit logging for failure
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE,
                        LogLevel.ERROR, id, null, ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CREDENTIAL_UPDATE + vaultId);
            } catch (Exception ex) {
                logger.error("Failed to create audit log: {}", ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Delete a credential.
     * 
     * @param id      - The credential ID
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @throws Exception If credential not found, access denied, or deletion fails
     */
    @Override
    @Transactional
    public void deleteCredential(String id, String vaultId, String userId) throws Exception {
        try {
            // First perform the standard deletion process
            deleteCredentialInternal(id, vaultId, userId);

            // If blockchain is enabled, mark as deleted on blockchain
            if (blockchainFeatureEnabled && blockchainVerifier != null) {
                try {
                    // Since the credential is already deleted from the database,
                    // we need to create a basic DTO with deletion marker
                    CredentialDTO dtoForBlockchain = new CredentialDTO();
                    dtoForBlockchain.setId(id);
                    dtoForBlockchain.setVaultId(vaultId);
                    dtoForBlockchain.setUserId(userId);
                    dtoForBlockchain.setDeleted(true);
                    dtoForBlockchain.setDeletedAt(LocalDateTime.now());

                    // Compute hash with deletion info and update on blockchain
                    String deletionHash = blockchainVerifier.computeCredentialHash(dtoForBlockchain);
                    blockchainVerifier.storeCredentialHash(id, deletionHash).thenAccept(txHash -> {
                        logger.info("Credential marked as deleted on blockchain. TxHash: {}", txHash);
                    }).exceptionally(ex -> {
                        logger.error("Failed to mark credential as deleted on blockchain: {}", ex.getMessage(), ex);
                        return null;
                    });
                } catch (Exception e) {
                    logger.error("Error marking credential as deleted on blockchain: {}", e.getMessage(), e);
                    // Continue with deletion even if blockchain update fails
                }
            }
        } catch (Exception e) {
            // The audit log is already handled in deleteCredentialInternal
            throw e;
        }
    }

    /**
     * Internal method to handle credential deletion without blockchain integration. Returns the username of the deleted
     * credential for use in blockchain recording.
     */
    private void deleteCredentialInternal(String id, String vaultId, String userId) throws Exception {
        try {
            // Find credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new Exception("Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Verify vault ownership
            if (!credential.getVaultId().equals(vaultId)) {
                logger.warn("Credential {} does not belong to vault {}", id, vaultId);
                throw new Exception("Credential not found in specified vault");
            }

            // Verify user ownership
            if (!credential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to delete credential {} belonging to user {}", userId, id,
                        credential.getUserId());
                throw new SecurityException("Access denied");
            }

            // Get credential details before deletion for audit logs and blockchain
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";

            // Delete credential
            credentialRepository.deleteById(id);
            logger.info("Credential deleted with ID: {}", id);

            // Add audit logging after successful deletion
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_DELETE, OperationType.DELETE, LogLevel.INFO,
                        id, username, ActionStatus.SUCCESS, null,
                        String.format(AuditLogMessages.CREDENTIAL_DELETED, vaultId));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            // Get vault name for notification
            Optional<com.lockbox.model.Vault> vaultOpt = vaultService.findById(vaultId);
            String vaultName = "";
            if (vaultOpt.isPresent()) {
                vaultName = vaultOpt.get().getName();
            }

            // After credential is deleted but before returning
            try {
                notificationCreationService.createCredentialDeletedNotification(userId, username, vaultName);
            } catch (Exception e) {
                logger.error("Failed to create credential deletion notification: {}", e.getMessage());
            }
        } catch (Exception e) {
            // Add audit logging for failure
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_DELETE, OperationType.DELETE,
                        LogLevel.ERROR, id, null, ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CREDENTIAL_DELETE + vaultId);
            } catch (Exception ex) {
                logger.error("Failed to create audit log: {}", ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Toggle favorite status for a credential.
     * 
     * @param id      - The credential ID
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @return Updated {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or update fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO toggleFavoriteStatus(String id, String vaultId, String userId) throws Exception {
        try {
            // Find credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new Exception("Credential not found");
            }

            Credential encryptedCredential = credentialOpt.get();

            // Verify vault ownership
            if (!encryptedCredential.getVaultId().equals(vaultId)) {
                logger.warn("Credential {} does not belong to vault {}", id, vaultId);
                throw new Exception("Credential not found in specified vault");
            }

            // Verify user ownership
            if (!encryptedCredential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to update credential {} belonging to user {}", userId, id,
                        encryptedCredential.getUserId());
                throw new SecurityException("Access denied");
            }

            // Decrypt credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);

            // Toggle favorite status
            boolean isFavorite = String.valueOf(Boolean.TRUE).equals(decryptedCredential.getFavorite());
            decryptedCredential.setFavorite(isFavorite ? String.valueOf(Boolean.FALSE) : String.valueOf(Boolean.TRUE));
            decryptedCredential.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Credential encryptedUpdatedCredential = credentialServerEncryptionService
                    .encryptServerData(decryptedCredential);
            Credential savedCredential = credentialRepository.save(encryptedUpdatedCredential);

            Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);
            CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);
            String username = decryptedSavedCredential.getUsername() != null ? decryptedSavedCredential.getUsername()
                    : "";

            try {
                boolean isFavoriteNew = !String.valueOf(Boolean.TRUE).equals(decryptedCredential.getFavorite());
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE, LogLevel.INFO,
                        id, username, ActionStatus.SUCCESS, null,
                        "Credential favorite status changed to " + (isFavoriteNew ? "favorite" : "not favorite"));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
        } catch (Exception e) {
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE,
                        LogLevel.ERROR, id, null, "FAILURE", e.getMessage(),
                        "Failed to toggle favorite status for credential");
            } catch (Exception ex) {
                logger.error("Failed to create audit log: {}", ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Update last used timestamp for a credential.
     * 
     * @param id      - The credential ID
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @return Updated {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or update fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO updateLastUsed(String id, String vaultId, String userId) throws Exception {
        // Find credential
        Optional<Credential> credentialOpt = credentialRepository.findById(id);
        if (!credentialOpt.isPresent()) {
            logger.warn("Credential not found with ID: {}", id);
            throw new Exception("Credential not found");
        }

        Credential encryptedCredential = credentialOpt.get();

        // Verify vault ownership
        if (!encryptedCredential.getVaultId().equals(vaultId)) {
            logger.warn("Credential {} does not belong to vault {}", id, vaultId);
            throw new Exception("Credential not found in specified vault");
        }

        // Verify user ownership
        if (!encryptedCredential.getUserId().equals(userId)) {
            logger.warn("User {} attempted to update credential {} belonging to user {}", userId, id,
                    encryptedCredential.getUserId());
            throw new SecurityException("Access denied");
        }

        // Decrypt credential
        Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);

        // Update last used timestamp
        decryptedCredential.setLastUsed(LocalDateTime.now());

        // Encrypt and save
        Credential encryptedUpdatedCredential = credentialServerEncryptionService
                .encryptServerData(decryptedCredential);
        Credential savedCredential = credentialRepository.save(encryptedUpdatedCredential);

        // Decrypt for response
        Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

        // Convert to DTO and encrypt for client response
        CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);
        return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
    }

    /**
     * Find credentials by domain for the current user.
     * 
     * @param domain - The domain to search for
     * @param userId - The current user ID
     * @return {@link CredentialListResponseDTO} containing encrypted credentials matching the domain
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public CredentialListResponseDTO findCredentialsByDomain(String domainId, String userId) throws Exception {
        List<Credential> encryptedCredentials = credentialRepository.findByDomainIdAndUserId(domainId, userId);

        List<Credential> decryptedCredentials = new ArrayList<>();
        // Decrypt each credential
        for (Credential encryptedCredential : encryptedCredentials) {
            decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
        }

        // Map to DTOs
        List<CredentialDTO> credentialDTOs = credentialMapper.toDTOList(decryptedCredentials);

        // Encrypt for client response with "Domain View" as vault name
        return credentialClientEncryptionService.encryptCredentialListForClient(credentialDTOs, "Domain View");
    }

    /**
     * Find favorite credentials for the current user.
     * 
     * @param userId - The current user ID
     * @return {@link CredentialListResponseDTO} containing encrypted favorite credentials
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public CredentialListResponseDTO findFavoriteCredentials(String userId) throws Exception {
        List<Credential> encryptedCredentials = credentialRepository.findByUserIdAndFavorite(userId,
                String.valueOf(Boolean.TRUE));

        List<Credential> decryptedCredentials = new ArrayList<>();
        // Decrypt each credential
        for (Credential encryptedCredential : encryptedCredentials) {
            decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
        }

        // Map to DTOs
        List<CredentialDTO> credentialDTOs = credentialMapper.toDTOList(decryptedCredentials);

        // Encrypt for client response with "Favorites" as vault name
        return credentialClientEncryptionService.encryptCredentialListForClient(credentialDTOs, "Favorites");
    }

    /**
     * Find a credential by ID (internal method).
     * 
     * @param id - The credential ID
     * @return Optional {@link Credential} entity
     * @throws Exception If retrieval fails
     */
    @Override
    public Optional<Credential> findById(String id) throws Exception {
        return credentialRepository.findById(id);
    }

    /**
     * Verify the integrity of a credential using blockchain
     * 
     * @param id      - The credential ID
     * @param vaultId - The vault ID
     * @param userId  - The current user ID for authorization
     * @return true if credential integrity is verified, false otherwise
     * @throws Exception if verification fails
     */
    @Override
    public boolean verifyCredentialIntegrity(String id, String vaultId, String userId) throws Exception {
        if (!blockchainFeatureEnabled || blockchainVerifier == null) {
            logger.info("Blockchain verification is disabled");
            return true; // If blockchain is disabled, assume integrity is fine
        }

        try {
            // Find credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new Exception("Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Verify vault ownership
            if (!credential.getVaultId().equals(vaultId)) {
                logger.warn("Credential {} does not belong to vault {}", id, vaultId);
                throw new Exception("Credential not found in specified vault");
            }

            // Verify user ownership
            if (!credential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to access credential {} belonging to user {}", userId, id,
                        credential.getUserId());
                throw new SecurityException("Access denied");
            }

            // Decrypt credential for verification
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);
            CredentialDTO dto = credentialMapper.toDTO(decryptedCredential);

            try {
                String credentialHash = blockchainVerifier.computeCredentialHash(dto);

                // First check if credential exists on blockchain
                String storedHash = blockchainVerifier.getCredentialHash(id);

                if (storedHash == null || storedHash.isEmpty()) {
                    logger.info("Credential {} not found on blockchain. Recording it now.", id);

                    // Store synchronously and wait for confirmation
                    try {
                        String txHash = blockchainVerifier.storeCredentialHashAndWait(id, credentialHash);
                        logger.info("Credential hash stored and confirmed on blockchain. TxHash: {}", txHash);

                        // Add retry mechanism with exponential backoff
                        storedHash = retryBlockchainRead(id, 5, 1000);

                        if (storedHash == null || storedHash.isEmpty()) {
                            logger.error("Credential still not found on blockchain after recording and retries");
                            return false;
                        }
                    } catch (Exception e) {
                        logger.error("Error while adding credential hash to blockchain: {}", e.getMessage(), e);
                        return false;
                    }
                }

                // Now verify the hash matches
                boolean hashMatches = credentialHash.equals(storedHash);

                if (!hashMatches) {
                    logger.warn("Credential {} hash mismatch. Possible data tampering.", id);

                    try {
                        auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VERIFY, OperationType.READ,
                                LogLevel.WARNING, id, null, ActionStatus.FAILURE, "Hash mismatch",
                                "Credential integrity verification failed - hash mismatch");
                    } catch (Exception e) {
                        logger.error("Failed to create audit log: {}", e.getMessage());
                    }
                } else {
                    try {
                        auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VERIFY, OperationType.READ,
                                LogLevel.INFO, id, null, ActionStatus.SUCCESS, null,
                                "Credential integrity verification successful");
                    } catch (Exception e) {
                        logger.error("Failed to create audit log: {}", e.getMessage());
                    }
                }

                return hashMatches;

            } catch (Exception e) {
                logger.error("Error verifying credential integrity: {}", e.getMessage(), e);
                return false;
            }
        } catch (Exception e) {
            logger.error("Exception in credential integrity verification: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Helper method to retry reading a credential hash from blockchain with exponential backoff
     * 
     * @param credentialId   The credential ID
     * @param maxRetries     Maximum number of retries
     * @param initialDelayMs Initial delay in milliseconds
     * @return The credential hash, or null if not found after retries
     */
    private String retryBlockchainRead(String credentialId, int maxRetries, long initialDelayMs) {
        String storedHash = null;
        long delay = initialDelayMs;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                Thread.sleep(delay);

                try {
                    storedHash = blockchainVerifier.getCredentialHash(credentialId);

                    if (storedHash != null && !storedHash.isEmpty()) {
                        logger.info("Successfully read credential hash on retry attempt {} using direct call", attempt);
                        return storedHash;
                    }
                } catch (Exception e) {
                    logger.debug("Error on direct call: {}", e.getMessage());
                }

                logger.info("Credential hash still not found on blockchain, retry attempt {}/{}", attempt, maxRetries);

                // Exponential backoff: double the delay for next retry
                delay *= 1.5;

            } catch (Exception e) {
                logger.warn("Error during blockchain read retry: {}", e.getMessage());
            }
        }

        return null;
    }
}