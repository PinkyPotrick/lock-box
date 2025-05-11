package com.lockbox.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Credential;

/**
 * Repository interface for {@link Credential} entity. Provides methods to query and manage credential records in the
 * database.
 */
@Repository
public interface CredentialRepository extends JpaRepository<Credential, String> {

    /**
     * Find all credentials belonging to a specific vault.
     * 
     * @param vaultId - The vault ID to filter by
     * @return List of credentials in the specified vault
     */
    List<Credential> findByVaultId(String vaultId);

    /**
     * Find credentials belonging to a specific vault with pagination.
     * 
     * @param vaultId  - The vault ID to filter by
     * @param pageable - Pagination information
     * @return Page of credentials in the specified vault
     */
    Page<Credential> findByVaultId(String vaultId, Pageable pageable);

    /**
     * Find credentials in a vault ordered by domain name in ascending order.
     * 
     * @param vaultId  - The vault ID to filter by
     * @param pageable - Pagination information
     * @return Page of credentials ordered by domain name (ascending)
     */
    @Query(value = "SELECT c FROM Credential c LEFT JOIN Domain d ON c.domainId = d.id "
            + "WHERE c.vaultId = :vaultId ORDER BY d.name ASC")
    Page<Credential> findByVaultIdOrderByDomainNameAsc(@Param("vaultId") String vaultId, Pageable pageable);

    /**
     * Find credentials in a vault ordered by domain name in descending order.
     * 
     * @param vaultId  - The vault ID to filter by
     * @param pageable - Pagination information
     * @return Page of credentials ordered by domain name (descending)
     */
    @Query(value = "SELECT c FROM Credential c LEFT JOIN Domain d ON c.domainId = d.id "
            + "WHERE c.vaultId = :vaultId ORDER BY d.name DESC")
    Page<Credential> findByVaultIdOrderByDomainNameDesc(@Param("vaultId") String vaultId, Pageable pageable);

    /**
     * Count the number of credentials in a specific vault.
     * 
     * @param vaultId - The vault ID to count credentials for
     * @return Count of credentials in the vault
     */
    int countByVaultId(String vaultId);

    /**
     * Find all credentials belonging to a specific user.
     * 
     * @param userId - The user ID to filter by
     * @return List of credentials owned by the specified user
     */
    List<Credential> findByUserId(String userId);

    /**
     * Find credentials belonging to a specific user with pagination.
     * 
     * @param userId   - The user ID to filter by
     * @param pageable - Pagination information
     * @return Page of credentials owned by the specified user
     */
    Page<Credential> findByUserId(String userId, Pageable pageable);

    /**
     * Find favorite credentials for a specific user.
     * 
     * @param userId   - The user ID to filter by
     * @param favorite - The favorite status to filter by
     * @return List of favorite credentials for the specified user
     */
    List<Credential> findByUserIdAndFavorite(String userId, String favorite);

    /**
     * Find credentials associated with a specific domain for a user.
     * 
     * @param domainId - The domain ID to filter by
     * @param userId   - The user ID to filter by
     * @return List of credentials for the specified domain and user
     */
    List<Credential> findByDomainIdAndUserId(String domainId, String userId);

    /**
     * Count the number of credentials associated with a specific domain for a user.
     * 
     * @param domainId - The domain ID to count credentials for
     * @param userId   - The user ID to filter by
     * @return Count of credentials for the specified domain and user
     */
    int countByDomainIdAndUserId(String domainId, String userId);

    /**
     * Count the total number of credentials for a specific user.
     * 
     * @param userId - The user ID to count credentials for
     * @return Total count of credentials for the user
     */
    int countByUserId(String userId);

    /**
     * Count the number of credentials associated with a specific domain.
     * 
     * @param domainId - The domain ID to count credentials for
     * @return Count of credentials for the specified domain
     */
    int countByDomainId(String domainId);

    /**
     * Delete all credentials in a specific vault and return the count of deleted items.
     * 
     * @param vaultId - The vault ID to delete credentials from
     * @return Count of deleted credentials
     */
    int deleteByVaultId(String vaultId);
}