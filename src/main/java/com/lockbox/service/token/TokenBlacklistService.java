package com.lockbox.service.token;

/**
 * Service for managing blacklisted JWT tokens
 */
public interface TokenBlacklistService {

    /**
     * Add a token to the blacklist
     * 
     * @param token The token to blacklist
     */
    void blacklistToken(String token);

    /**
     * Check if a token is blacklisted
     * 
     * @param token The token to check
     * @return true if the token is blacklisted, false otherwise
     */
    boolean isTokenBlacklisted(String token);

    /**
     * Remove expired tokens from the blacklist
     */
    void purgeExpiredTokens();
}