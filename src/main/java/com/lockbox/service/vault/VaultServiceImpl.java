package com.lockbox.service.vault;

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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lockbox.dto.vault.VaultDTO;
import com.lockbox.dto.vault.VaultListResponseDTO;
import com.lockbox.dto.vault.VaultMapper;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.dto.vault.VaultResponseDTO;
import com.lockbox.model.User;
import com.lockbox.model.Vault;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.repository.UserRepository;
import com.lockbox.repository.VaultRepository;
import com.lockbox.validators.VaultValidator;

/**
 * Implementation of the {@link VaultService} interface. Provides functionality for managing {@link Vault} entities.
 */
@Service
public class VaultServiceImpl implements VaultService {

    private final Logger logger = LoggerFactory.getLogger(VaultServiceImpl.class);

    @Autowired
    private VaultRepository vaultRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private VaultServerEncryptionService vaultServerEncryptionService;

    @Autowired
    private VaultClientEncryptionService vaultClientEncryptionService;

    @Autowired
    private VaultValidator vaultValidator;

    @Autowired
    private VaultMapper vaultMapper;

    /**
     * Find all vaults for the current user with optional pagination.
     * 
     * @param userId - The current user ID
     * @param page   - Optional page number (0-based index), can be null
     * @param size   - Optional page size, can be null
     * @return {@link VaultListResponseDTO} containing encrypted vaults
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public VaultListResponseDTO findAllVaultsByUser(String userId, Integer page, Integer size) throws Exception {
        try {
            List<Vault> encryptedVaults;

            // Create pageable object inside the service if pagination parameters are provided
            if (page != null && size != null) {
                Pageable pageable = PageRequest.of(page, size);
                Page<Vault> vaultPage = vaultRepository.findByUserId(userId, pageable);
                encryptedVaults = vaultPage.getContent();
            } else {
                encryptedVaults = vaultRepository.findByUserId(userId);
            }

            List<Vault> decryptedVaults = new ArrayList<>();

            // Decrypt each vault retrieved from database
            for (Vault encryptedVault : encryptedVaults) {
                decryptedVaults.add(vaultServerEncryptionService.decryptServerData(encryptedVault));
            }

            // Convert to DTOs
            List<VaultDTO> vaultDTOs = vaultMapper.toDTOList(decryptedVaults);

            // Add credential count to each vault DTO
            for (VaultDTO dto : vaultDTOs) {
                int credentialCount = credentialRepository.countByVaultId(dto.getId());
                dto.setCredentialCount(credentialCount);
            }

            // Get the total count regardless of pagination
            int totalCount = vaultRepository.countByUserId(userId);

            // Encrypt for client response
            List<VaultResponseDTO> encryptedResponseDTOs = new ArrayList<>();
            for (VaultDTO vaultDTO : vaultDTOs) {
                encryptedResponseDTOs.add(vaultClientEncryptionService.encryptVaultForClient(vaultDTO));
            }

            return new VaultListResponseDTO(encryptedResponseDTOs, totalCount);
        } catch (Exception e) {
            logger.error("Error fetching vaults for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch vaults", e);
        }
    }

    /**
     * Find all vaults for the current user.
     * 
     * @param userId - The current user ID
     * @return {@link VaultListResponseDTO} containing encrypted vaults
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public VaultListResponseDTO findAllVaultsByUser(String userId) throws Exception {
        try {
            List<Vault> vaults = vaultRepository.findByUserId(userId);

            List<Vault> decryptedVaults = new ArrayList<>();
            for (Vault encryptedVault : vaults) {
                decryptedVaults.add(vaultServerEncryptionService.decryptServerData(encryptedVault));
            }

            // Convert to DTOs
            List<VaultDTO> vaultDTOs = vaultMapper.toDTOList(decryptedVaults);

            // Add credential count to each vault
            for (VaultDTO dto : vaultDTOs) {
                int credentialCount = credentialRepository.countByVaultId(dto.getId());
                dto.setCredentialCount(credentialCount);
            }

            // Instead of using vaultMapper.toResponseDTOList, use the client encryption service
            return vaultClientEncryptionService.encryptVaultListForClient(vaultDTOs);
        } catch (Exception e) {
            logger.error("Error fetching vaults for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch vaults", e);
        }
    }

    /**
     * Find all vaults for the current user with pagination.
     * 
     * @param userId   - The current user ID
     * @param pageable - The pagination information
     * @return {@link VaultListResponseDTO} containing encrypted vaults
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public VaultListResponseDTO findAllVaultsByUser(String userId, Pageable pageable) throws Exception {
        try {
            // Get paginated results
            Page<Vault> encryptedVaultsPage = vaultRepository.findByUserId(userId, pageable);
            List<Vault> decryptedVaults = new ArrayList<>();

            // Decrypt each vault retrieved from database
            for (Vault encryptedVault : encryptedVaultsPage.getContent()) {
                decryptedVaults.add(vaultServerEncryptionService.decryptServerData(encryptedVault));
            }

            // Convert to DTOs
            List<VaultDTO> vaultDTOs = vaultMapper.toDTOList(decryptedVaults);

            // Add credential count to each vault DTO
            for (VaultDTO dto : vaultDTOs) {
                int credentialCount = credentialRepository.countByVaultId(dto.getId());
                dto.setCredentialCount(credentialCount);
            }

            // Get the total count regardless of pagination
            int totalCount = vaultRepository.countByUserId(userId);

            // Encrypt for client response and include total count
            List<VaultResponseDTO> encryptedVaults = new ArrayList<>();
            for (VaultDTO vaultDTO : vaultDTOs) {
                encryptedVaults.add(vaultClientEncryptionService.encryptVaultForClient(vaultDTO));
            }

            return new VaultListResponseDTO(encryptedVaults, totalCount);
        } catch (Exception e) {
            logger.error("Error fetching paginated vaults for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch vaults", e);
        }
    }

    /**
     * Find vault by ID.
     * 
     * @param id     - The vault ID
     * @param userId - The current user ID for authorization
     * @return {@link VaultResponseDTO} with encryption
     * @throws Exception If vault not found, access denied, or encryption fails
     */
    @Override
    public VaultResponseDTO findVaultById(String id, String userId) throws Exception {
        try {
            Optional<Vault> vaultOptional = vaultRepository.findById(id);
            if (!vaultOptional.isPresent()) {
                throw new Exception("Vault not found");
            }

            Vault vault = vaultOptional.get();

            // Check ownership
            if (!vault.getUser().getId().equals(userId)) {
                throw new SecurityException("Access denied");
            }

            // Decrypt server-side encrypted data
            Vault decryptedVault = vaultServerEncryptionService.decryptServerData(vault);

            // Convert to DTO
            VaultDTO vaultDTO = vaultMapper.toDTO(decryptedVault);

            // Encrypt for client
            return vaultClientEncryptionService.encryptVaultForClient(vaultDTO);
        } catch (Exception e) {
            logger.error("Error finding vault {} for user {}: {}", id, userId, e.getMessage());
            throw new Exception("Failed to find vault", e);
        }
    }

    /**
     * Create a new vault.
     * 
     * @param requestDTO - The encrypted vault request DTO
     * @param userId     - The current user ID
     * @return Created {@link VaultResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public VaultResponseDTO createVault(VaultRequestDTO requestDTO, String userId) throws Exception {
        try {
            // First decrypt the vault data, then validate
            VaultDTO vaultDTO = vaultClientEncryptionService.decryptVaultFromClient(requestDTO);
            vaultValidator.validateVaultDTO(vaultDTO);

            // Find the user
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                throw new RuntimeException("User not found");
            }

            // Create the vault entity
            Vault vault = vaultMapper.toEntity(vaultDTO, userOpt.get());

            // Set timestamps
            LocalDateTime now = LocalDateTime.now();
            vault.setCreatedAt(now);
            vault.setUpdatedAt(now);

            // Encrypt and save
            Vault encryptedVault = vaultServerEncryptionService.encryptServerData(vault);
            Vault savedVault = vaultRepository.save(encryptedVault);

            // Decrypt for response
            Vault decryptedVault = vaultServerEncryptionService.decryptServerData(savedVault);

            // Convert to DTO
            VaultDTO responseDTO = vaultMapper.toDTO(decryptedVault);
            responseDTO.setCredentialCount(0); // New vault has no credentials

            // Encrypt for client response
            return vaultClientEncryptionService.encryptVaultForClient(responseDTO);
        } catch (Exception e) {
            logger.error("Error creating vault: {}", e.getMessage());
            throw new Exception("Failed to create vault", e);
        }
    }

    /**
     * Update an existing vault.
     * 
     * @param id         - The vault ID
     * @param requestDTO - The encrypted vault request DTO
     * @param userId     - The current user ID for authorization
     * @return Updated {@link VaultResponseDTO} with encryption
     * @throws Exception If vault not found, access denied, or update fails
     */
    @Override
    @Transactional
    public VaultResponseDTO updateVault(String id, VaultRequestDTO requestDTO, String userId) throws Exception {
        try {
            Optional<Vault> vaultOptional = vaultRepository.findById(id);
            if (!vaultOptional.isPresent()) {
                throw new Exception("Vault not found");
            }

            Vault vault = vaultOptional.get();

            // Check ownership
            if (!vault.getUser().getId().equals(userId)) {
                throw new SecurityException("Access denied");
            }

            // Validate the update request first
            vaultValidator.validateVaultUpdateRequest(requestDTO);

            // Decrypt the request data
            VaultDTO decryptedVaultDTO = vaultClientEncryptionService.decryptVaultFromClient(requestDTO);

            // Update the vault
            Vault updatedVault = vaultMapper.updateEntityFromDTO(vault, decryptedVaultDTO);

            // Update timestamp
            updatedVault.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Vault encryptedVault = vaultServerEncryptionService.encryptServerData(updatedVault);
            Vault savedVault = vaultRepository.save(encryptedVault);

            // Decrypt for response
            Vault decryptedVault = vaultServerEncryptionService.decryptServerData(savedVault);

            // Convert to DTO
            VaultDTO responseDTO = vaultMapper.toDTO(decryptedVault);

            // Add credential count
            int credentialCount = credentialRepository.countByVaultId(id);
            responseDTO.setCredentialCount(credentialCount);

            // Encrypt for client response
            return vaultClientEncryptionService.encryptVaultForClient(responseDTO);
        } catch (Exception e) {
            logger.error("Error updating vault {}: {}", id, e.getMessage());
            throw new Exception("Failed to update vault", e);
        }
    }

    /**
     * Delete a vault by ID.
     * 
     * @param id     - The vault ID
     * @param userId - The current user ID for authorization
     * @throws Exception If vault not found, access denied, or deletion fails
     */
    @Override
    @Transactional
    public void deleteVault(String id, String userId) throws Exception {
        try {
            // Check if vault exists
            Optional<Vault> vaultOpt = findById(id);
            if (!vaultOpt.isPresent()) {
                logger.warn("Vault not found with ID: {}", id);
                throw new RuntimeException("Vault not found");
            }

            Vault vault = vaultOpt.get();

            // Ensure the user has access to this vault
            if (!vault.getUser().getId().equals(userId)) {
                logger.warn("User {} attempted to delete vault {} belonging to user {}", userId, id,
                        vault.getUser().getId());
                throw new RuntimeException("Access denied");
            }

            // Check if vault has credentials
            int credentialCount = credentialRepository.countByVaultId(id);
            if (credentialCount > 0) {
                throw new RuntimeException("Cannot delete vault that contains credentials");
            }

            // Delete the vault
            vaultRepository.deleteById(id);
            logger.info("Vault deleted with ID: {}", id);
        } catch (Exception e) {
            logger.error("Error deleting vault {}: {}", id, e.getMessage());
            throw new Exception("Failed to delete vault", e);
        }
    }

    /**
     * Check if a vault is owned by the specified user.
     * 
     * @param vaultId - The vault ID to check
     * @param userId  - The user ID to check against
     * @return true if the vault exists and is owned by the user, false otherwise
     * @throws Exception If the check fails
     */
    @Override
    public boolean isVaultOwnedByUser(String vaultId, String userId) throws Exception {
        try {
            Optional<Vault> vaultOpt = findById(vaultId);
            if (!vaultOpt.isPresent()) {
                return false;
            }

            Vault vault = vaultOpt.get();
            return vault.getUser().getId().equals(userId);
        } catch (Exception e) {
            logger.error("Error checking vault ownership: {}", e.getMessage());
            throw new Exception("Failed to check vault ownership", e);
        }
    }

    /**
     * Internal method to find vault by ID.
     * 
     * @param id - The vault ID
     * @return Optional {@link Vault} entity
     * @throws Exception If retrieval or decryption fails
     */
    @Override
    public Optional<Vault> findById(String id) throws Exception {
        Optional<Vault> encryptedVaultOpt = vaultRepository.findById(id);

        if (!encryptedVaultOpt.isPresent()) {
            return Optional.empty();
        }

        Vault decryptedVault = vaultServerEncryptionService.decryptServerData(encryptedVaultOpt.get());
        return Optional.of(decryptedVault);
    }

    /**
     * Count vaults by user ID.
     * 
     * @param userId - The user ID
     * @return Count of vaults
     */
    @Override
    public int countByUserId(String userId) {
        return vaultRepository.countByUserId(userId);
    }
}