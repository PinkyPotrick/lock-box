package com.lockbox.service.domain;

import java.util.Optional;

import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.model.Domain;

public interface DomainService {

    /**
     * Find all domains for current user
     * 
     * @param userId The current user ID
     * @return List response DTO of domains
     */
    DomainListResponseDTO findAllDomainsByUser(String userId) throws Exception;

    /**
     * Find domain by ID
     * 
     * @param id     The domain ID
     * @param userId The current user ID for authorization
     * @return Domain response DTO
     * @throws Exception If domain not found or access denied
     */
    DomainResponseDTO findDomainById(String id, String userId) throws Exception;

    /**
     * Create a new domain
     * 
     * @param requestDTO The domain request DTO
     * @param userId     The current user ID
     * @return Created domain response DTO
     */
    DomainResponseDTO createDomain(DomainRequestDTO requestDTO, String userId) throws Exception;

    /**
     * Update an existing domain
     * 
     * @param id         The domain ID
     * @param requestDTO The domain request DTO
     * @param userId     The current user ID for authorization
     * @return Updated domain response DTO
     * @throws Exception If domain not found, access denied, or update fails
     */
    DomainResponseDTO updateDomain(String id, DomainRequestDTO requestDTO, String userId) throws Exception;

    /**
     * Delete a domain by ID
     * 
     * @param id     The domain ID
     * @param userId The current user ID for authorization
     * @throws Exception If domain not found, access denied, or deletion fails
     */
    void deleteDomain(String id, String userId) throws Exception;

    /**
     * Find domains by name search for current user
     * 
     * @param query  The search query
     * @param userId The current user ID
     * @return List response DTO of matching domains
     */
    DomainListResponseDTO searchDomainsByName(String query, String userId) throws Exception;

    /**
     * Verify domain by URL and return matching domain if exists
     * 
     * @param url    The URL to verify
     * @param userId The current user ID
     * @return Domain response DTO if found, or null
     */
    DomainResponseDTO verifyDomainByUrl(String url, String userId) throws Exception;

    /**
     * Get the count of credentials for a domain
     * 
     * @param id     The domain ID
     * @param userId The current user ID for authorization
     * @return Count of credentials for the domain
     * @throws Exception If domain not found, access denied, or count fails
     */
    int getCredentialCountInDomain(String id, String userId) throws Exception;

    // Keep these methods for internal use within service layer

    /**
     * Internal method to find domain by ID
     * 
     * @param id The domain ID
     * @return Optional domain entity
     */
    Optional<Domain> findById(String id) throws Exception;

    /**
     * Update the last used timestamp for a domain
     * 
     * @param id The domain ID
     */
    void updateLastUsed(String id) throws Exception;

    /**
     * Count domains by user ID
     * 
     * @param userId The user ID
     * @return Count of domains
     */
    int countByUserId(String userId);
}