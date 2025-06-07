package com.lockbox.service.credential;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialMapper;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.model.ActionType;
import com.lockbox.model.Credential;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
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

            // Decrypt credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);

            // Convert to DTO
            CredentialDTO credentialDTO = credentialMapper.toDTO(decryptedCredential);

            // Prepare a descriptive name for credential name
            String domain = decryptedCredential.getDomainId() != null ? decryptedCredential.getDomainId() : "";
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Add audit logging right before returning the response
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VIEW, OperationType.READ, LogLevel.INFO, id,
                        credentialName, ActionStatus.SUCCESS, null,
                        String.format(AppConstants.AuditLogMessages.CREDENTIAL_VIEWED, vaultId));
            } catch (Exception e) {
                // Don't fail the credential view if logging fails
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            // Encrypt for client response
            return credentialClientEncryptionService.encryptCredentialForClient(credentialDTO);
        } catch (Exception e) {
            // Add audit logging for failure
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_VIEW, OperationType.READ, LogLevel.WARNING,
                        id, null, ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CREDENTIAL_VIEW + vaultId);
            } catch (Exception ex) {
                // Don't stop the original exception propagation if logging fails
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

            // Decrypt for response
            Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and encrypt for client response
            CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);

            // Prepare a descriptive name for credential name
            String domain = decryptedSavedCredential.getDomainId() != null ? decryptedSavedCredential.getDomainId()
                    : "";
            String username = decryptedSavedCredential.getUsername() != null ? decryptedSavedCredential.getUsername()
                    : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Add audit logging before returning
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_CREATE, OperationType.WRITE, LogLevel.INFO,
                        savedCredential.getId(), credentialName, ActionStatus.SUCCESS, null,
                        String.format(AuditLogMessages.CREDENTIAL_CREATED, vaultId));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
        } catch (Exception e) {
            // Decrypt the request
            CredentialDTO credentialDTO = credentialClientEncryptionService.decryptCredentialFromClient(requestDTO);

            // Prepare a descriptive name for credential name
            String domain = credentialDTO.getDomainId() != null ? credentialDTO.getDomainId() : "";
            String username = credentialDTO.getUsername() != null ? credentialDTO.getUsername() : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Add audit logging for failure
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_CREATE, OperationType.WRITE, LogLevel.ERROR,
                        null, credentialName != null ? credentialName : "New Credential", ActionStatus.FAILURE,
                        e.getMessage(), AuditLogMessages.FAILED_CREDENTIAL_CREATE + vaultId);
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
            String domain = decryptedCredential.getDomainId() != null ? decryptedCredential.getDomainId() : "";
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Add audit logging before returning
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE, LogLevel.INFO,
                        id, credentialName, ActionStatus.SUCCESS, null,
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
                notificationCreationService.createCredentialUpdatedNotification(userId, credentialName, vaultName, id,
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

            // Get name before decryption for audit log
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);

            // Prepare a descriptive name for credential name
            String domain = decryptedCredential.getDomainId() != null ? decryptedCredential.getDomainId() : "";
            String username = decryptedCredential.getUsername() != null ? decryptedCredential.getUsername() : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Delete credential
            credentialRepository.deleteById(id);
            logger.info("Credential deleted with ID: {}", id);

            // Add audit logging after successful deletion
            try {
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_DELETE, OperationType.DELETE, LogLevel.INFO,
                        id, credentialName, ActionStatus.SUCCESS, null,
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
                notificationCreationService.createCredentialDeletedNotification(userId, credentialName, vaultName);
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

            // Decrypt for response
            Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and encrypt for client response
            CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);

            // Prepare a descriptive name for credential name
            String domain = decryptedSavedCredential.getDomainId() != null ? decryptedSavedCredential.getDomainId()
                    : "";
            String username = decryptedSavedCredential.getUsername() != null ? decryptedSavedCredential.getUsername()
                    : "";
            String credentialName = (domain.isEmpty() ? "" : domain + " - ")
                    + (username.isEmpty() ? "Credential" : username);

            // Add audit logging before returning
            try {
                boolean isFavoriteNew = !String.valueOf(Boolean.TRUE).equals(decryptedCredential.getFavorite());
                auditLogService.logUserAction(userId, ActionType.CREDENTIAL_UPDATE, OperationType.UPDATE, LogLevel.INFO,
                        id, credentialName, ActionStatus.SUCCESS, null,
                        "Credential favorite status changed to " + (isFavoriteNew ? "favorite" : "not favorite"));
            } catch (Exception e) {
                logger.error("Failed to create audit log: {}", e.getMessage());
            }

            return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
        } catch (Exception e) {
            // Add audit logging for failure
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
}