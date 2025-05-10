package com.lockbox.service.domain;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainMapper;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.model.Domain;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.repository.DomainRepository;
import com.lockbox.validators.DomainValidator;

@Service
public class DomainServiceImpl implements DomainService {

    private final Logger logger = LoggerFactory.getLogger(DomainServiceImpl.class);

    @Autowired
    private DomainRepository domainRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private DomainServerEncryptionService domainServerEncryptionService;

    @Autowired
    private DomainValidator domainValidator;

    @Autowired
    private DomainMapper domainMapper;

    @Override
    public DomainListResponseDTO findAllDomainsByUser(String userId) throws Exception {
        try {
            List<Domain> encryptedDomains = domainRepository.findByUserId(userId);
            List<Domain> decryptedDomains = new ArrayList<>();

            for (Domain encryptedDomain : encryptedDomains) {
                decryptedDomains.add(domainServerEncryptionService.decryptServerData(encryptedDomain));
            }

            List<DomainResponseDTO> responseDTOs = domainMapper.toResponseDTOList(decryptedDomains);

            // Add credential counts
            for (DomainResponseDTO dto : responseDTOs) {
                int credentialCount = credentialRepository.countByDomainId(dto.getId());
                dto.setCredentialCount(credentialCount);
            }

            return new DomainListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error fetching domains for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch domains");
        }
    }

    @Override
    public DomainResponseDTO findDomainById(String id, String userId) throws Exception {
        Optional<Domain> domainOpt = findById(id);

        if (!domainOpt.isPresent()) {
            logger.warn("Domain not found with ID: {}", id);
            throw new RuntimeException("Domain not found");
        }

        Domain domain = domainOpt.get();

        // Ensure the user has access to this domain
        if (!domain.getUserId().equals(userId)) {
            logger.warn("User {} attempted to access domain {} belonging to user {}", userId, id, domain.getUserId());
            throw new RuntimeException("Access denied");
        }

        // Update last used timestamp
        updateLastUsed(id);

        // Create the response DTO
        DomainResponseDTO responseDTO = domainMapper.toResponseDTO(domain);

        // Add credential count
        int credentialCount = credentialRepository.countByDomainId(id);
        responseDTO.setCredentialCount(credentialCount);

        return responseDTO;
    }

    @Override
    public DomainResponseDTO createDomain(DomainRequestDTO requestDTO, String userId) throws Exception {
        try {
            // Set the user ID to the current user
            requestDTO.setUserId(userId);

            // Validate the request
            domainValidator.validateDomainRequest(requestDTO);

            // Convert to entity
            Domain domain = domainMapper.toEntity(requestDTO);

            // Set creation timestamp
            LocalDateTime now = LocalDateTime.now();
            domain.setCreatedAt(now);
            domain.setUpdatedAt(now);

            // Encrypt and save
            Domain encryptedDomain = domainServerEncryptionService.encryptServerData(domain);
            Domain savedDomain = domainRepository.save(encryptedDomain);

            // Decrypt saved domain
            Domain decryptedDomain = domainServerEncryptionService.decryptServerData(savedDomain);

            // Convert to DTO and return
            DomainResponseDTO responseDTO = domainMapper.toResponseDTO(decryptedDomain);
            responseDTO.setCredentialCount(0); // New domain has no credentials

            return responseDTO;
        } catch (Exception e) {
            logger.error("Error creating domain: {}", e.getMessage());
            throw new Exception("Failed to create domain");
        }
    }

    @Override
    public DomainResponseDTO updateDomain(String id, DomainRequestDTO requestDTO, String userId) throws Exception {
        try {
            // Check if domain exists
            Optional<Domain> domainOpt = findById(id);
            if (!domainOpt.isPresent()) {
                logger.warn("Domain not found with ID: {}", id);
                throw new RuntimeException("Domain not found");
            }

            Domain existingDomain = domainOpt.get();

            // Ensure the user has access to this domain
            if (!existingDomain.getUserId().equals(userId)) {
                logger.warn("User {} attempted to update domain {} belonging to user {}", userId, id,
                        existingDomain.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Set the user ID to prevent changes
            requestDTO.setUserId(userId);

            // Validate the request
            domainValidator.validateDomainRequest(requestDTO);

            // Update the entity from the request
            Domain updatedDomain = domainMapper.updateEntityFromDTO(existingDomain, requestDTO);

            // Update timestamp
            updatedDomain.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Domain encryptedDomain = domainServerEncryptionService.encryptServerData(updatedDomain);
            Domain savedDomain = domainRepository.save(encryptedDomain);

            // Decrypt saved domain
            Domain decryptedDomain = domainServerEncryptionService.decryptServerData(savedDomain);

            // Convert to DTO
            DomainResponseDTO responseDTO = domainMapper.toResponseDTO(decryptedDomain);

            // Add credential count
            int credentialCount = credentialRepository.countByDomainId(id);
            responseDTO.setCredentialCount(credentialCount);

            return responseDTO;
        } catch (Exception e) {
            logger.error("Error updating domain {}: {}", id, e.getMessage());
            throw new Exception("Failed to update domain");
        }
    }

    @Override
    public void deleteDomain(String id, String userId) throws Exception {
        try {
            // Check if domain exists
            Optional<Domain> domainOpt = findById(id);
            if (!domainOpt.isPresent()) {
                logger.warn("Domain not found with ID: {}", id);
                throw new RuntimeException("Domain not found");
            }

            Domain domain = domainOpt.get();

            // Ensure the user has access to this domain
            if (!domain.getUserId().equals(userId)) {
                logger.warn("User {} attempted to delete domain {} belonging to user {}", userId, id,
                        domain.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Check if domain has credentials
            int credentialCount = credentialRepository.countByDomainId(id);
            if (credentialCount > 0) {
                throw new RuntimeException("Cannot delete domain that has associated credentials");
            }

            // Delete the domain
            domainRepository.deleteById(id);
            logger.info("Domain deleted with ID: {}", id);
        } catch (Exception e) {
            logger.error("Error deleting domain {}: {}", id, e.getMessage());
            throw new Exception("Failed to delete domain", e);
        }
    }

    @Override
    public DomainListResponseDTO searchDomainsByName(String query, String userId) throws Exception {
        try {
            // Find domains that match the search query
            List<Domain> encryptedDomains = domainRepository.findByNameContainingAndUserId(query, userId);
            List<Domain> decryptedDomains = new ArrayList<>();

            for (Domain encryptedDomain : encryptedDomains) {
                decryptedDomains.add(domainServerEncryptionService.decryptServerData(encryptedDomain));
            }

            List<DomainResponseDTO> responseDTOs = domainMapper.toResponseDTOList(decryptedDomains);

            // Add credential counts
            for (DomainResponseDTO dto : responseDTOs) {
                int credentialCount = credentialRepository.countByDomainId(dto.getId());
                dto.setCredentialCount(credentialCount);
            }

            return new DomainListResponseDTO(responseDTOs, responseDTOs.size());
        } catch (Exception e) {
            logger.error("Error searching domains for query '{}': {}", query, e.getMessage());
            throw new Exception("Failed to search domains");
        }
    }

    @Override
    public DomainResponseDTO verifyDomainByUrl(String url, String userId) throws Exception {
        try {
            // Normalize the URL (remove protocol, www, etc.)
            String normalizedUrl = domainValidator.normalizeUrl(url);

            // Check if a domain with this URL exists for the user
            Optional<Domain> existingDomainOpt = domainRepository.findByUrlAndUserId(normalizedUrl, userId);

            if (existingDomainOpt.isPresent()) {
                // Domain exists, decrypt it
                Domain decryptedDomain = domainServerEncryptionService.decryptServerData(existingDomainOpt.get());

                // Update last used timestamp
                updateLastUsed(decryptedDomain.getId());

                // Convert to DTO
                DomainResponseDTO responseDTO = domainMapper.toResponseDTO(decryptedDomain);

                // Add credential count
                int credentialCount = credentialRepository.countByDomainId(decryptedDomain.getId());
                responseDTO.setCredentialCount(credentialCount);

                return responseDTO;
            } else {
                // No matching domain found
                logger.debug("No domain found for URL: {} (normalized to: {})", url, normalizedUrl);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error verifying domain by URL '{}': {}", url, e.getMessage());
            throw new Exception("Failed to verify domain");
        }
    }

    @Override
    public int getCredentialCountInDomain(String id, String userId) throws Exception {
        try {
            // Check if domain exists
            Optional<Domain> domainOpt = findById(id);
            if (!domainOpt.isPresent()) {
                logger.warn("Domain not found with ID: {}", id);
                throw new RuntimeException("Domain not found");
            }

            Domain domain = domainOpt.get();

            // Ensure the user has access to this domain
            if (!domain.getUserId().equals(userId)) {
                logger.warn("User {} attempted to access domain {} belonging to user {}", userId, id,
                        domain.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Return credential count
            return credentialRepository.countByDomainId(id);
        } catch (Exception e) {
            logger.error("Error getting credential count for domain {}: {}", id, e.getMessage());
            throw new Exception("Failed to get credential count");
        }
    }

    @Override
    public Optional<Domain> findById(String id) throws Exception {
        Optional<Domain> encryptedDomainOpt = domainRepository.findById(id);

        if (!encryptedDomainOpt.isPresent()) {
            return Optional.empty();
        }

        Domain decryptedDomain = domainServerEncryptionService.decryptServerData(encryptedDomainOpt.get());
        return Optional.of(decryptedDomain);
    }

    @Override
    public void updateLastUsed(String id) throws Exception {
        try {
            Optional<Domain> domainOpt = domainRepository.findById(id);

            if (domainOpt.isPresent()) {
                Domain domain = domainOpt.get();

                // Decrypt for manipulation
                Domain decryptedDomain = domainServerEncryptionService.decryptServerData(domain);

                // Re-encrypt and save
                Domain encryptedDomain = domainServerEncryptionService.encryptServerData(decryptedDomain);
                domainRepository.save(encryptedDomain);

                logger.debug("Updated last used timestamp for domain {}", id);
            } else {
                logger.warn("Could not update last used timestamp. Domain not found with ID: {}", id);
            }
        } catch (Exception e) {
            logger.error("Error updating last used timestamp for domain {}: {}", id, e.getMessage());
            throw new Exception("Failed to update last used timestamp", e);
        }
    }

    @Override
    public int countByUserId(String userId) {
        return domainRepository.countByUserId(userId);
    }
}