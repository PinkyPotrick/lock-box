package com.lockbox.service.credential;

import java.util.Optional;

import com.lockbox.dto.credential.CredentialListResponseDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.dto.credential.CredentialResponseDTO;
import com.lockbox.model.Credential;

public interface CredentialService {

    /**
     * Find all credentials for current user
     * 
     * @param userId The current user ID
     * @return List response DTO of credentials
     */
    CredentialListResponseDTO findAllCredentialsByUser(String userId) throws Exception;

    /**
     * Find credential by ID
     * 
     * @param id     The credential ID
     * @param userId The current user ID for authorization
     * @return Credential response DTO
     * @throws Exception If credential not found or access denied
     */
    CredentialResponseDTO findCredentialById(String id, String userId) throws Exception;

    /**
     * Create a new credential
     * 
     * @param requestDTO The credential request DTO
     * @param userId     The current user ID
     * @return Created credential response DTO
     */
    CredentialResponseDTO createCredential(CredentialRequestDTO requestDTO, String userId) throws Exception;

    /**
     * Update an existing credential
     * 
     * @param id         The credential ID
     * @param requestDTO The credential request DTO
     * @param userId     The current user ID for authorization
     * @return Updated credential response DTO
     * @throws Exception If credential not found, access denied, or update fails
     */
    CredentialResponseDTO updateCredential(String id, CredentialRequestDTO requestDTO, String userId) throws Exception;

    /**
     * Delete a credential by ID
     * 
     * @param id     The credential ID
     * @param userId The current user ID for authorization
     * @throws Exception If credential not found, access denied, or deletion fails
     */
    void deleteCredential(String id, String userId) throws Exception;

    /**
     * Toggle favorite status for a credential
     * 
     * @param id     The credential ID
     * @param userId The current user ID for authorization
     * @return Updated credential response DTO
     * @throws Exception If credential not found, access denied, or update fails
     */
    CredentialResponseDTO toggleFavorite(String id, String userId) throws Exception;

    /**
     * Find credentials by domain ID for current user
     * 
     * @param domainId The domain ID
     * @param userId   The current user ID
     * @return List response DTO of credentials
     */
    CredentialListResponseDTO findCredentialsByDomain(String domainId, String userId) throws Exception;

    /**
     * Find credentials by vault ID for current user
     * 
     * @param vaultId The vault ID
     * @param userId  The current user ID
     * @return List response DTO of credentials
     */
    CredentialListResponseDTO findCredentialsByVault(String vaultId, String userId) throws Exception;

    /**
     * Find favorite credentials for current user
     * 
     * @param userId The current user ID
     * @return List response DTO of favorite credentials
     */
    CredentialListResponseDTO findFavoriteCredentials(String userId) throws Exception;

    // Keep these methods for internal use within service layer

    /**
     * Internal method to find credential by ID
     * 
     * @param id The credential ID
     * @return Optional credential entity
     */
    Optional<Credential> findById(String id) throws Exception;

    /**
     * Update the last used timestamp for a credential
     * 
     * @param id The credential ID
     */
    void updateLastUsed(String id) throws Exception;

    /**
     * Count credentials by user ID
     * 
     * @param userId The user ID
     * @return Count of credentials
     */
    int countByUserId(String userId);
}