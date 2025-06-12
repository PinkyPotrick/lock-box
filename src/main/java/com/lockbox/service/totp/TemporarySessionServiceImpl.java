package com.lockbox.service.totp;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@Service
public class TemporarySessionServiceImpl implements TemporarySessionService {

    private static final Logger logger = LoggerFactory.getLogger(TemporarySessionServiceImpl.class);

    private static final int SESSION_EXPIRATION_MINUTES = 2;

    // Cache for temporary sessions with 2-minute expiration
    private final Cache<String, String> temporarySessions = CacheBuilder.newBuilder()
            .expireAfterWrite(SESSION_EXPIRATION_MINUTES, TimeUnit.MINUTES).build();

    /**
     * Create a new temporary session for a user pending TOTP verification
     * 
     * @param userId The user ID
     * @return The session ID for the temporary session
     */
    @Override
    public String createTemporarySession(String userId) {
        String sessionId = generateSessionId();
        temporarySessions.put(sessionId, userId);
        logger.debug("Created temporary session {} for user {}", sessionId, userId);
        return sessionId;
    }

    /**
     * Validate a temporary session and return the associated user ID
     * 
     * @param sessionId The temporary session ID
     * @return The user ID associated with the session, or null if invalid
     */
    @Override
    public String validateTemporarySession(String sessionId) {
        String userId = temporarySessions.getIfPresent(sessionId);
        if (userId == null) {
            logger.debug("Invalid or expired temporary session: {}", sessionId);
            return null;
        }
        logger.debug("Validated temporary session {} for user {}", sessionId, userId);
        return userId;
    }

    /**
     * Remove a temporary session
     * 
     * @param sessionId The temporary session ID to remove
     */
    @Override
    public void removeTemporarySession(String sessionId) {
        temporarySessions.invalidate(sessionId);
        logger.debug("Removed temporary session: {}", sessionId);
    }

    /**
     * Generate a random session ID
     */
    private String generateSessionId() {
        return "totp-" + UUID.randomUUID().toString();
    }
}