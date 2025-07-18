package com.lockbox.service.token;

public interface TokenBlacklistService {

    void blacklistToken(String token);

    boolean isTokenBlacklisted(String token);

    void purgeExpiredTokens();
}