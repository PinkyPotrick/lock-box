package com.lockbox.repository;

import com.lockbox.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository interface for {@link User} entity. Provides methods to query and manage user records in the database.
 */
@Repository
public interface UserRepository extends JpaRepository<User, String> {

    /**
     * Find a user by their username.
     * 
     * @param username - The username to search for
     * @return The user with the specified username, or null if not found
     */
    User findByUsername(String username);

    /**
     * Find a user by their email address.
     * 
     * @param email - The email address to search for
     * @return The user with the specified email address, or null if not found
     */
    User findByEmail(String email);
}