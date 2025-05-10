package com.lockbox.service.credential;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialMapper;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.model.Credential;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.validators.CredentialValidator;

@Service
public class CredentialServiceImpl implements CredentialService {

    private final Logger logger = LoggerFactory.getLogger(CredentialServiceImpl.class);

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private CredentialServerEncryptionService credentialServerEncryptionService;

    @Autowired
    private CredentialValidator credentialValidator;

    @Autowired
    private CredentialMapper credentialMapper;

    @Override
    public CredentialListResponseDTO findAllCredentialsByUser(String userId) throws Exception {
        try {
            List<Credential> encryptedCredentials = credentialRepository.findByUserId(userId);
            List<Credential> decryptedCredentials = new ArrayList<>();

            for (Credential encryptedCredential : encryptedCredentials) {
                decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
            }

            List<CredentialResponseDTO> responseDTOs = credentialMapper.toResponseDTOList(decryptedCredentials);
            return new CredentialListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error fetching credentials for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch credentials");
        }
    }

    @Override
    public CredentialResponseDTO findCredentialById(String id, String userId) throws Exception {
        Optional<Credential> credentialOpt = findById(id);

        if (!credentialOpt.isPresent()) {
            logger.warn("Credential not found with ID: {}", id);
            throw new RuntimeException("Credential not found");
        }

        Credential credential = credentialOpt.get();

        // Ensure the user has access to this credential
        if (!credential.getUserId().equals(userId)) {
            logger.warn("User {} attempted to access credential {} belonging to user {}", userId, id,
                    credential.getUserId());
            throw new RuntimeException("Access denied");
        }

        // Update last used timestamp
        updateLastUsed(id);

        // Return the response DTO
        return credentialMapper.toResponseDTO(credential);
    }

    @Override
    public CredentialResponseDTO createCredential(CredentialRequestDTO requestDTO, String userId) throws Exception {
        try {
            // Set the user ID to the current user
            requestDTO.setUserId(userId);

            // Convert to entity
            Credential credential = credentialMapper.toEntity(requestDTO);

            // Validate credential
            credentialValidator.validate(credential);

            // Set creation timestamp
            LocalDateTime now = LocalDateTime.now();
            credential.setCreatedAt(now);
            credential.setUpdatedAt(now);

            // Set default values if needed
            if (credential.getFavorite() == null) {
                credential.setFavorite("false");
            }

            // Encrypt and save
            Credential encryptedCredential = credentialServerEncryptionService.encryptServerData(credential);
            Credential savedCredential = credentialRepository.save(encryptedCredential);

            // Decrypt saved credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and return
            return credentialMapper.toResponseDTO(decryptedCredential);
        } catch (Exception e) {
            logger.error("Error creating credential: {}", e.getMessage());
            throw new Exception("Failed to create credential");
        }
    }

    @Override
    public CredentialResponseDTO updateCredential(String id, CredentialRequestDTO requestDTO, String userId)
            throws Exception {
        try {
            // Check if credential exists
            Optional<Credential> credentialOpt = findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new RuntimeException("Credential not found");
            }

            Credential existingCredential = credentialOpt.get();

            // Ensure the user has access to this credential
            if (!existingCredential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to update credential {} belonging to user {}", userId, id,
                        existingCredential.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Set the user ID to prevent changes
            requestDTO.setUserId(userId);

            // Update the entity from the request
            Credential updatedCredential = credentialMapper.updateEntityFromDTO(existingCredential, requestDTO);

            // Validate credential
            credentialValidator.validate(updatedCredential);

            // Update timestamp
            updatedCredential.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Credential encryptedCredential = credentialServerEncryptionService.encryptServerData(updatedCredential);
            Credential savedCredential = credentialRepository.save(encryptedCredential);

            // Decrypt saved credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and return
            return credentialMapper.toResponseDTO(decryptedCredential);
        } catch (Exception e) {
            logger.error("Error updating credential {}: {}", id, e.getMessage());
            throw new Exception("Failed to update credential");
        }
    }

    @Override
    public void deleteCredential(String id, String userId) throws Exception {
        try {
            // Check if credential exists
            Optional<Credential> credentialOpt = findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new RuntimeException("Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Ensure the user has access to this credential
            if (!credential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to delete credential {} belonging to user {}", userId, id,
                        credential.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Delete the credential
            credentialRepository.deleteById(id);
            logger.info("Credential deleted with ID: {}", id);
        } catch (Exception e) {
            logger.error("Error deleting credential {}: {}", id, e.getMessage());
            throw new Exception("Failed to delete credential", e);
        }
    }

    @Override
    public CredentialResponseDTO toggleFavorite(String id, String userId) throws Exception {
        try {
            // Check if credential exists
            Optional<Credential> credentialOpt = findById(id);
            if (!credentialOpt.isPresent()) {
                logger.warn("Credential not found with ID: {}", id);
                throw new RuntimeException("Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Ensure the user has access to this credential
            if (!credential.getUserId().equals(userId)) {
                logger.warn("User {} attempted to update credential {} belonging to user {}", userId, id,
                        credential.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Toggle favorite status
            boolean isFavorite = Boolean.parseBoolean(credential.getFavorite());
            credential.setFavorite(String.valueOf(!isFavorite));

            // Update timestamp
            credential.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Credential encryptedCredential = credentialServerEncryptionService.encryptServerData(credential);
            Credential savedCredential = credentialRepository.save(encryptedCredential);

            // Decrypt saved credential
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(savedCredential);

            // Convert to DTO and return
            return credentialMapper.toResponseDTO(decryptedCredential);
        } catch (Exception e) {
            logger.error("Error toggling favorite for credential {}: {}", id, e.getMessage());
            throw new Exception("Failed to update favorite status", e);
        }
    }

    @Override
    public CredentialListResponseDTO findCredentialsByDomain(String domainId, String userId) throws Exception {
        try {
            List<Credential> encryptedCredentials = credentialRepository.findByUserIdAndDomainId(userId, domainId);
            List<Credential> decryptedCredentials = new ArrayList<>();

            for (Credential encryptedCredential : encryptedCredentials) {
                decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
            }

            List<CredentialResponseDTO> responseDTOs = credentialMapper.toResponseDTOList(decryptedCredentials);
            return new CredentialListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error fetching credentials for domain {}: {}", domainId, e.getMessage());
            throw new Exception("Failed to fetch credentials for domain", e);
        }
    }

    @Override
    public CredentialListResponseDTO findCredentialsByVault(String vaultId, String userId) throws Exception {
        try {
            List<Credential> encryptedCredentials = credentialRepository.findByVaultId(vaultId);
            List<Credential> decryptedCredentials = new ArrayList<>();

            // Filter for current user's credentials
            for (Credential encryptedCredential : encryptedCredentials) {
                if (encryptedCredential.getUserId().equals(userId)) {
                    decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
                }
            }

            List<CredentialResponseDTO> responseDTOs = credentialMapper.toResponseDTOList(decryptedCredentials);
            return new CredentialListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error fetching credentials for vault {}: {}", vaultId, e.getMessage());
            throw new Exception("Failed to fetch credentials for vault", e);
        }
    }

    @Override
    public CredentialListResponseDTO findFavoriteCredentials(String userId) throws Exception {
        try {
            List<Credential> encryptedCredentials = credentialRepository.findByUserIdAndFavorite(userId,
                    Boolean.TRUE.toString());
            List<Credential> decryptedCredentials = new ArrayList<>();

            for (Credential encryptedCredential : encryptedCredentials) {
                decryptedCredentials.add(credentialServerEncryptionService.decryptServerData(encryptedCredential));
            }

            List<CredentialResponseDTO> responseDTOs = credentialMapper.toResponseDTOList(decryptedCredentials);
            return new CredentialListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error fetching favorite credentials for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch favorite credentials", e);
        }
    }

    @Override
    public Optional<Credential> findById(String id) throws Exception {
        Optional<Credential> encryptedCredentialOpt = credentialRepository.findById(id);

        if (!encryptedCredentialOpt.isPresent()) {
            return Optional.empty();
        }

        Credential decryptedCredential = credentialServerEncryptionService
                .decryptServerData(encryptedCredentialOpt.get());

        return Optional.of(decryptedCredential);
    }

    @Override
    public void updateLastUsed(String id) throws Exception {
        try {
            Optional<Credential> credentialOpt = credentialRepository.findById(id);

            if (credentialOpt.isPresent()) {
                Credential credential = credentialOpt.get();

                // Decrypt for manipulation
                Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);

                // Update last used timestamp
                decryptedCredential.setLastUsed(LocalDateTime.now());

                // Re-encrypt and save
                Credential encryptedCredential = credentialServerEncryptionService
                        .encryptServerData(decryptedCredential);
                credentialRepository.save(encryptedCredential);

                logger.debug("Updated last used timestamp for credential {}", id);
            } else {
                logger.warn("Could not update last used timestamp. Credential not found with ID: {}", id);
            }
        } catch (Exception e) {
            logger.error("Error updating last used timestamp for credential {}: {}", id, e.getMessage());
            throw new Exception("Failed to update last used timestamp", e);
        }
    }

    @Override
    public int countByUserId(String userId) {
        return credentialRepository.countByUserId(userId);
    }
}