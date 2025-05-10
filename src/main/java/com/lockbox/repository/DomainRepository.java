package com.lockbox.repository;

import com.lockbox.model.Domain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DomainRepository extends JpaRepository<Domain, String> {

    /**
     * Find domains by user ID
     * 
     * @param userId The user ID
     * @return List of domains
     */
    List<Domain> findByUserId(String userId);

    /**
     * Find domain by URL and user ID
     * 
     * @param url    The normalized URL
     * @param userId The user ID
     * @return Optional domain
     */
    Optional<Domain> findByUrlAndUserId(String url, String userId);

    /**
     * Find domains by name containing search string and user ID
     * 
     * @param name   The search string
     * @param userId The user ID
     * @return List of domains
     */
    List<Domain> findByNameContainingAndUserId(String name, String userId);

    /**
     * Count domains by user ID
     * 
     * @param userId The user ID
     * @return Count of domains
     */
    int countByUserId(String userId);
}