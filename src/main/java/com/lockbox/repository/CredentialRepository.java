package com.lockbox.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Credential;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, String> {

    /**
     * Find credentials by user ID
     * 
     * @param userId The user ID
     * @return List of credentials
     */
    List<Credential> findByUserId(String userId);

    /**
     * Find credentials by domain ID
     * 
     * @param domainId The domain ID
     * @return List of credentials
     */
    List<Credential> findByDomainId(String domainId);

    /**
     * Find credentials by vault ID
     * 
     * @param vaultId The vault ID
     * @return List of credentials
     */
    List<Credential> findByVaultId(String vaultId);

    /**
     * Find credentials by user ID and domain ID
     * 
     * @param userId   The user ID
     * @param domainId The domain ID
     * @return List of credentials
     */
    List<Credential> findByUserIdAndDomainId(String userId, String domainId);

    /**
     * Count credentials by user ID
     * 
     * @param userId The user ID
     * @return Count of credentials
     */
    int countByUserId(String userId);

    /**
     * Count credentials by domain ID
     * 
     * @param domainId The domain ID
     * @return Count of credentials
     */
    int countByDomainId(String domainId);

    /**
     * Count credentials by vault ID
     * 
     * @param vaultId The vault ID
     * @return Count of credentials
     */
    int countByVaultId(String vaultId);

    /**
     * Delete credentials by domain ID
     * 
     * @param domainId The domain ID
     */
    void deleteByDomainId(String domainId);

    /**
     * Delete credentials by vault ID
     * 
     * @param vaultId The vault ID
     */
    void deleteByVaultId(String vaultId);

    /**
     * Find favorite credentials by user ID
     * 
     * @param userId   The user ID
     * @param favorite Whether the credentials are marked as favorite
     * @return List of credentials
     */
    List<Credential> findByUserIdAndFavorite(String userId, String favorite);
}