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
import com.lockbox.model.Credential;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.service.vault.VaultService;
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

    /**
     * Find all credentials for a specific vault with optional pagination.
     * 
     * @param vaultId   The vault ID
     * @param userId    The current user ID for authorization
     * @param page      Optional page number (0-based)
     * @param size      Optional page size
     * @param sort      Optional field to sort by
     * @param direction Optional sort direction ("ASC" or "DESC")
     * @return {@link CredentialListResponseDTO} containing encrypted credentials
     * @throws Exception If vault not found, access denied, or retrieval fails
     */
    @Override
    public CredentialListResponseDTO findAllCredentialsByVault(String vaultId, String userId, Integer page,
            Integer size, String sort, String direction) throws Exception {
        // Verify vault ownership and get vault
        Optional<com.lockbox.model.Vault> vaultOpt = vaultService.findById(vaultId);
        if (!vaultOpt.isPresent() || !vaultOpt.get().getUser().getId().equals(userId)) {
            logger.warn("User {} attempted to access vault {} they don't own", userId, vaultId);
            throw new SecurityException("Access denied");
        }

        // Get vault name for response
        String vaultName = vaultOpt.get().getName();

        List<Credential> encryptedCredentials;
        int totalCount;

        // Handle pagination if specified
        if (page != null && size != null) {
            Sort.Direction sortDir = Sort.Direction.DESC; // Default direction
            if (direction != null && direction.equalsIgnoreCase("ASC")) {
                sortDir = Sort.Direction.ASC;
            }

            if (sort != null && sort.equals("domain")) {
                // For domain sorting, we need a pageable without sort
                Pageable pageable = PageRequest.of(page, size);

                // Use special repository methods for domain sorting
                Page<Credential> credentialPage;
                if (sortDir == Sort.Direction.ASC) {
                    credentialPage = credentialRepository.findByVaultIdOrderByDomainNameAsc(vaultId, pageable);
                } else {
                    credentialPage = credentialRepository.findByVaultIdOrderByDomainNameDesc(vaultId, pageable);
                }
                encryptedCredentials = credentialPage.getContent();
            } else {
                // For all other sorts, use the standard approach
                String sortField = "updatedAt"; // Default sort field
                if (sort != null && !sort.isEmpty()) {
                    sortField = sort;
                }

                Pageable pageable = PageRequest.of(page, size, Sort.by(sortDir, sortField));
                Page<Credential> credentialPage = credentialRepository.findByVaultId(vaultId, pageable);
                encryptedCredentials = credentialPage.getContent();
            }
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
     * Find all credentials for a specific vault.
     * 
     * @param vaultId The vault ID
     * @param userId  The current user ID for authorization
     * @return {@link CredentialListResponseDTO} containing encrypted credentials
     * @throws Exception If vault not found, access denied, or retrieval fails
     */
    @Override
    public CredentialListResponseDTO findAllCredentialsByVault(String vaultId, String userId) throws Exception {
        // Delegate to the paginated method with null pagination parameters
        return findAllCredentialsByVault(vaultId, userId, null, null, null, null);
    }

    /**
     * Find a specific credential by ID.
     * 
     * @param id      The credential ID
     * @param vaultId The vault ID
     * @param userId  The current user ID for authorization
     * @return {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or retrieval fails
     */
    @Override
    public CredentialResponseDTO findCredentialById(String id, String vaultId, String userId) throws Exception {
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
            logger.warn("User {} attempted to access credential {} belonging to user {}", userId, id,
                    encryptedCredential.getUserId());
            throw new SecurityException("Access denied");
        }

        // Decrypt credential
        Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(encryptedCredential);

        // Convert to DTO
        CredentialDTO credentialDTO = credentialMapper.toDTO(decryptedCredential);

        // Encrypt for client response
        return credentialClientEncryptionService.encryptCredentialForClient(credentialDTO);
    }

    /**
     * Create a new credential.
     * 
     * @param requestDTO The encrypted credential request DTO
     * @param vaultId    The vault ID to add the credential to
     * @param userId     The current user ID for authorization
     * @return Created {@link CredentialResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO createCredential(CredentialRequestDTO requestDTO, String vaultId, String userId)
            throws Exception {
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
        credential
                .setFavorite(credentialDTO.isFavorite() ? String.valueOf(Boolean.TRUE) : String.valueOf(Boolean.FALSE));

        // Encrypt and save
        Credential encryptedCredential = credentialServerEncryptionService.encryptServerData(credential);
        Credential savedCredential = credentialRepository.save(encryptedCredential);

        // Decrypt for response
        Credential decryptedSavedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

        // Convert to DTO and encrypt for client response
        CredentialDTO savedDTO = credentialMapper.toDTO(decryptedSavedCredential);
        return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
    }

    /**
     * Update an existing credential.
     * 
     * @param id         The credential ID
     * @param requestDTO The encrypted credential request DTO
     * @param vaultId    The vault ID
     * @param userId     The current user ID for authorization
     * @return Updated {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or update fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO updateCredential(String id, CredentialRequestDTO requestDTO, String vaultId,
            String userId) throws Exception {
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
        return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
    }

    /**
     * Delete a credential.
     * 
     * @param id      The credential ID
     * @param vaultId The vault ID
     * @param userId  The current user ID for authorization
     * @throws Exception If credential not found, access denied, or deletion fails
     */
    @Override
    @Transactional
    public void deleteCredential(String id, String vaultId, String userId) throws Exception {
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

        // Delete credential
        credentialRepository.deleteById(id);
        logger.info("Credential deleted with ID: {}", id);
    }

    /**
     * Toggle favorite status for a credential.
     * 
     * @param id      The credential ID
     * @param vaultId The vault ID
     * @param userId  The current user ID for authorization
     * @return Updated {@link CredentialResponseDTO} with encryption
     * @throws Exception If credential not found, access denied, or update fails
     */
    @Override
    @Transactional
    public CredentialResponseDTO toggleFavoriteStatus(String id, String vaultId, String userId) throws Exception {
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
        return credentialClientEncryptionService.encryptCredentialForClient(savedDTO);
    }

    /**
     * Update last used timestamp for a credential.
     * 
     * @param id      The credential ID
     * @param vaultId The vault ID
     * @param userId  The current user ID for authorization
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
     * @param domain The domain to search for
     * @param userId The current user ID
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
     * @param userId The current user ID
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
     * @param id The credential ID
     * @return Optional {@link Credential} entity
     * @throws Exception If retrieval fails
     */
    @Override
    public Optional<Credential> findById(String id) throws Exception {
        return credentialRepository.findById(id);
    }
}