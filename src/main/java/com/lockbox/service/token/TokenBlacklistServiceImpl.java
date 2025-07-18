package com.lockbox.service.token;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.lockbox.utils.AppConstants.TokenMessages;

@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {

    private final Logger logger = LoggerFactory.getLogger(TokenBlacklistServiceImpl.class);

    // Store tokens with their expiration time
    private final Map<String, Date> blacklistedTokens = new ConcurrentHashMap<>();

    @Autowired
    private TokenService tokenService;

    @Override
    public void blacklistToken(String token) {
        try {
            // Get token expiration time
            Date expiry = tokenService.getExpirationDateFromToken(token);
            blacklistedTokens.put(token, expiry);
            logger.debug(TokenMessages.TOKEN_BLACKLISTED, expiry);
        } catch (Exception e) {
            // If we can't parse the token, blacklist it anyway with a default expiry
            Date defaultExpiry = new Date(System.currentTimeMillis() + 3600000); // 1 hour
            blacklistedTokens.put(token, defaultExpiry);
            logger.warn(TokenMessages.TOKEN_EXPIRY_EXTRACTION_ERROR);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.containsKey(token);
    }

    @Override
    @Scheduled(fixedRate = 3600000) // Run every hour
    public void purgeExpiredTokens() {
        Date now = new Date();
        int count = 0;

        logger.debug(TokenMessages.TOKEN_PURGE_START);
        for (Map.Entry<String, Date> entry : blacklistedTokens.entrySet()) {
            if (entry.getValue().before(now)) {
                blacklistedTokens.remove(entry.getKey());
                count++;
            }
        }

        if (count > 0) {
            logger.debug(TokenMessages.TOKEN_PURGE_COMPLETE, count);
        }
    }
}