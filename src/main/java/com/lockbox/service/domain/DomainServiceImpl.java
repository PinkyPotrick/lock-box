package com.lockbox.service.domain;

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

import com.lockbox.dto.domain.DomainDTO;
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainMapper;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.model.Domain;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.repository.DomainRepository;
import com.lockbox.validators.DomainValidator;

/**
 * Implementation of the {@link DomainService} interface. Provides functionality for managing {@link Domain} entities.
 */
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
    private DomainClientEncryptionService domainClientEncryptionService;

    @Autowired
    private DomainValidator domainValidator;

    @Autowired
    private DomainMapper domainMapper;

    /**
     * Find all domains for the current user with optional pagination.
     * 
     * @param userId - The current user ID
     * @param page   - Optional page number (0-based index), can be null
     * @param size   - Optional page size, can be null
     * @return {@link DomainListResponseDTO} containing encrypted domains
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public DomainListResponseDTO findAllDomainsByUser(String userId, Integer page, Integer size) throws Exception {
        try {
            List<Domain> encryptedDomains;

            // Create pageable object inside the service if pagination parameters are provided
            if (page != null && size != null) {
                Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "updatedAt"));
                Page<Domain> domainPage = domainRepository.findByUserId(userId, pageable);
                encryptedDomains = domainPage.getContent();
            } else {
                encryptedDomains = domainRepository.findByUserId(userId);
            }

            List<Domain> decryptedDomains = new ArrayList<>();

            // Decrypt each domain retrieved from database
            for (Domain encryptedDomain : encryptedDomains) {
                decryptedDomains.add(domainServerEncryptionService.decryptServerData(encryptedDomain));
            }

            // Convert to DTOs
            List<DomainDTO> domainDTOs = domainMapper.toDTOList(decryptedDomains);

            // Add credential count to each domain DTO
            for (DomainDTO dto : domainDTOs) {
                int credentialCount = credentialRepository.countByDomainIdAndUserId(dto.getId(), userId);
                dto.setCredentialCount(credentialCount);
            }

            // Get the total count regardless of pagination
            int totalCount = domainRepository.countByUserId(userId);

            // Encrypt for client response and include total count
            DomainListResponseDTO response = domainClientEncryptionService.encryptDomainListForClient(domainDTOs);
            response.setTotalCount(totalCount);

            return response;
        } catch (Exception e) {
            logger.error("Error fetching domains for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch domains", e);
        }
    }

    /**
     * Find all domains for the current user.
     * 
     * @param userId - The current user ID
     * @return {@link DomainListResponseDTO} containing encrypted domains
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public DomainListResponseDTO findAllDomainsByUser(String userId) throws Exception {
        // Simply delegate to the paginated method with null pagination parameters
        return findAllDomainsByUser(userId, null, null);
    }

    /**
     * Find all domains for the current user with pagination.
     * 
     * @param userId   - The current user ID
     * @param pageable - The pagination information
     * @return {@link DomainListResponseDTO} containing encrypted domains
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public DomainListResponseDTO findAllDomainsByUser(String userId, Pageable pageable) throws Exception {
        try {
            // Get paginated results
            Page<Domain> encryptedDomainsPage = domainRepository.findByUserId(userId, pageable);
            List<Domain> decryptedDomains = new ArrayList<>();

            // Decrypt each domain retrieved from database
            for (Domain encryptedDomain : encryptedDomainsPage.getContent()) {
                decryptedDomains.add(domainServerEncryptionService.decryptServerData(encryptedDomain));
            }

            // Convert to DTOs
            List<DomainDTO> domainDTOs = domainMapper.toDTOList(decryptedDomains);

            // Add credential count to each domain DTO
            for (DomainDTO dto : domainDTOs) {
                int credentialCount = credentialRepository.countByDomainIdAndUserId(dto.getId(), userId);
                dto.setCredentialCount(credentialCount);
            }

            // Get the total count regardless of pagination
            int totalCount = (int) encryptedDomainsPage.getTotalElements();

            // Encrypt for client response and include total count
            DomainListResponseDTO response = domainClientEncryptionService.encryptDomainListForClient(domainDTOs);
            response.setTotalCount(totalCount);

            return response;
        } catch (Exception e) {
            logger.error("Error fetching paginated domains for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch domains", e);
        }
    }

    /**
     * Find domain by ID.
     * 
     * @param id     - The domain ID
     * @param userId - The current user ID for authorization
     * @return {@link DomainResponseDTO} with encryption
     * @throws Exception If domain not found, access denied, or encryption fails
     */
    @Override
    public DomainResponseDTO findDomainById(String id, String userId) throws Exception {
        try {
            // Find domain
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

            // Convert to DTO
            DomainDTO domainDTO = domainMapper.toDTO(domain);

            // Add credential count
            int credentialCount = credentialRepository.countByDomainIdAndUserId(id, userId);
            domainDTO.setCredentialCount(credentialCount);

            // Encrypt for client response
            return domainClientEncryptionService.encryptDomainForClient(domainDTO);
        } catch (Exception e) {
            logger.error("Error fetching domain with ID {}: {}", id, e.getMessage());
            throw new Exception("Failed to fetch domain", e);
        }
    }

    /**
     * Create a new domain.
     * 
     * @param requestDTO - The encrypted domain request DTO
     * @param userId     - The current user ID
     * @return Created {@link DomainResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public DomainResponseDTO createDomain(DomainRequestDTO requestDTO, String userId) throws Exception {
        try {
            // Decrypt the request
            DomainDTO domainDTO = domainClientEncryptionService.decryptDomainFromClient(requestDTO);

            // Validate the decrypted data
            domainValidator.validateDomainDTO(domainDTO);

            // Create the domain entity
            Domain domain = domainMapper.toEntity(domainDTO);
            domain.setUserId(userId);

            // Set timestamps
            LocalDateTime now = LocalDateTime.now();
            domain.setCreatedAt(now);
            domain.setUpdatedAt(now);

            // Encrypt and save
            Domain encryptedDomain = domainServerEncryptionService.encryptServerData(domain);
            Domain savedDomain = domainRepository.save(encryptedDomain);

            // Decrypt for response
            Domain decryptedDomain = domainServerEncryptionService.decryptServerData(savedDomain);

            // Convert to DTO
            DomainDTO responseDTO = domainMapper.toDTO(decryptedDomain);
            responseDTO.setCredentialCount(0); // New domain has no credentials

            // Encrypt for client response
            return domainClientEncryptionService.encryptDomainForClient(responseDTO);
        } catch (Exception e) {
            logger.error("Error creating domain: {}", e.getMessage());
            throw new Exception("Failed to create domain", e);
        }
    }

    /**
     * Update an existing domain.
     * 
     * @param id         - The domain ID
     * @param requestDTO - The encrypted domain request DTO
     * @param userId     - The current user ID for authorization
     * @return Updated {@link DomainResponseDTO} with encryption
     * @throws Exception If domain not found, access denied, or update fails
     */
    @Override
    @Transactional
    public DomainResponseDTO updateDomain(String id, DomainRequestDTO requestDTO, String userId) throws Exception {
        try {
            // Decrypt the request
            DomainDTO domainDTO = domainClientEncryptionService.decryptDomainFromClient(requestDTO);

            // Validate the decrypted data
            domainValidator.validateDomainDTO(domainDTO);

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

            // Update the domain
            Domain updatedDomain = domainMapper.updateEntityFromDTO(existingDomain, domainDTO);

            // Update timestamp
            updatedDomain.setUpdatedAt(LocalDateTime.now());

            // Encrypt and save
            Domain encryptedDomain = domainServerEncryptionService.encryptServerData(updatedDomain);
            Domain savedDomain = domainRepository.save(encryptedDomain);

            // Decrypt for response
            Domain decryptedDomain = domainServerEncryptionService.decryptServerData(savedDomain);

            // Convert to DTO
            DomainDTO responseDTO = domainMapper.toDTO(decryptedDomain);

            // Add credential count
            int credentialCount = credentialRepository.countByDomainIdAndUserId(id, userId);
            responseDTO.setCredentialCount(credentialCount);

            // Encrypt for client response
            return domainClientEncryptionService.encryptDomainForClient(responseDTO);
        } catch (Exception e) {
            logger.error("Error updating domain {}: {}", id, e.getMessage());
            throw new Exception("Failed to update domain", e);
        }
    }

    /**
     * Delete a domain by ID.
     * 
     * @param id     - The domain ID
     * @param userId - The current user ID for authorization
     * @throws Exception If domain not found, access denied, or deletion fails
     */
    @Override
    @Transactional
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
            int credentialCount = credentialRepository.countByDomainIdAndUserId(id, userId);
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

    /**
     * Get the count of credentials for a domain.
     * 
     * @param domainId - The domain ID
     * @param userId   - The current user ID for authorization
     * @return Count of credentials for the domain
     * @throws Exception If domain not found, access denied, or count fails
     */
    @Override
    public int getCredentialCountForDomain(String domainId, String userId) throws Exception {
        try {
            // Check if domain exists
            Optional<Domain> domainOpt = findById(domainId);
            if (!domainOpt.isPresent()) {
                logger.warn("Domain not found with ID: {}", domainId);
                throw new RuntimeException("Domain not found");
            }

            Domain domain = domainOpt.get();

            // Ensure the user has access to this domain
            if (!domain.getUserId().equals(userId)) {
                logger.warn("User {} attempted to access domain {} belonging to user {}", userId, domainId,
                        domain.getUserId());
                throw new RuntimeException("Access denied");
            }

            // Get credential count
            return credentialRepository.countByDomainIdAndUserId(domainId, userId);
        } catch (Exception e) {
            logger.error("Error getting credential count for domain {}: {}", domainId, e.getMessage());
            throw new Exception("Failed to get credential count", e);
        }
    }

    /**
     * Check if a domain is owned by the specified user.
     * 
     * @param domainId - The domain ID to check
     * @param userId   - The user ID to check against
     * @return true if the domain exists and is owned by the user, false otherwise
     * @throws Exception If the check fails
     */
    @Override
    public boolean isDomainOwnedByUser(String domainId, String userId) throws Exception {
        try {
            Optional<Domain> domainOpt = findById(domainId);
            if (!domainOpt.isPresent()) {
                return false;
            }

            Domain domain = domainOpt.get();
            return domain.getUserId().equals(userId);
        } catch (Exception e) {
            logger.error("Error checking domain ownership: {}", e.getMessage());
            throw new Exception("Failed to check domain ownership", e);
        }
    }

    /**
     * Internal method to find domain by ID.
     * 
     * @param id - The domain ID
     * @return Optional {@link Domain} entity
     * @throws Exception If retrieval or decryption fails
     */
    @Override
    public Optional<Domain> findById(String id) throws Exception {
        Optional<Domain> encryptedDomainOpt = domainRepository.findById(id);

        if (!encryptedDomainOpt.isPresent()) {
            return Optional.empty();
        }

        Domain decryptedDomain = domainServerEncryptionService.decryptServerData(encryptedDomainOpt.get());
        return Optional.of(decryptedDomain);
    }

    /**
     * Count domains by user ID.
     * 
     * @param userId - The user ID
     * @return Count of domains
     */
    @Override
    public int countByUserId(String userId) {
        return domainRepository.countByUserId(userId);
    }
}