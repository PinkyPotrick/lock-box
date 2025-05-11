package com.lockbox.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Domain;

/**
 * Repository interface for {@link Domain} entities.
 */
@Repository
public interface DomainRepository extends JpaRepository<Domain, String> {

    /**
     * Find all domains by user ID
     * 
     * @param userId The user ID
     * @return List of domains
     */
    List<Domain> findByUserId(String userId);

    /**
     * Find all domains by user ID with pagination
     * 
     * @param userId   The user ID
     * @param pageable Pagination information
     * @return Page of domains
     */
    Page<Domain> findByUserId(String userId, Pageable pageable);

    /**
     * Count domains by user ID
     * 
     * @param userId The user ID
     * @return Count of domains
     */
    int countByUserId(String userId);
}