package com.lockbox.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Vault;

/**
 * Repository interface for {@link Vault} entities.
 */
@Repository
public interface VaultRepository extends JpaRepository<Vault, String> {

    /**
     * Find all vaults by user ID
     * 
     * @param userId The user ID
     * @return List of vaults
     */
    @Query("SELECT v FROM Vault v WHERE v.user.id = :userId")
    List<Vault> findByUserId(@Param("userId") String userId);

    /**
     * Find all vaults by user ID with pagination
     * 
     * @param userId   The user ID
     * @param pageable Pagination information
     * @return Page of vaults
     */
    @Query("SELECT v FROM Vault v WHERE v.user.id = :userId")
    Page<Vault> findByUserId(@Param("userId") String userId, Pageable pageable);

    /**
     * Count vaults by user ID
     * 
     * @param userId The user ID
     * @return Count of vaults
     */
    @Query("SELECT COUNT(v) FROM Vault v WHERE v.user.id = :userId")
    int countByUserId(@Param("userId") String userId);
}