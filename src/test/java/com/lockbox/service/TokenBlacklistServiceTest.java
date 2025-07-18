package com.lockbox.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.lockbox.service.token.TokenBlacklistServiceImpl;
import com.lockbox.service.token.TokenService;

class TokenBlacklistServiceTest {

    @Mock
    private TokenService tokenService;

    @InjectMocks
    private TokenBlacklistServiceImpl tokenBlacklistService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testBlacklistToken() {
        // Given
        String token = "test.jwt.token";
        Date expiry = new Date(System.currentTimeMillis() + 3600000); // 1 hour from now
        when(tokenService.getExpirationDateFromToken(token)).thenReturn(expiry);

        // When
        tokenBlacklistService.blacklistToken(token);

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token));
    }

    @Test
    void testBlacklistTokenWithExceptionHandling() {
        // Given
        String token = "invalid.token";
        when(tokenService.getExpirationDateFromToken(token)).thenThrow(new RuntimeException("Invalid token"));

        // When
        tokenBlacklistService.blacklistToken(token);

        // Then
        assertTrue(tokenBlacklistService.isTokenBlacklisted(token));
    }

    @Test
    void testPurgeExpiredTokens() {
        // Given
        String expiredToken = "expired.token";
        String validToken = "valid.token";

        // Mock an expired token (1 hour ago)
        Date pastDate = new Date(System.currentTimeMillis() - 3600000);
        when(tokenService.getExpirationDateFromToken(expiredToken)).thenReturn(pastDate);

        // Mock a valid token (1 hour from now)
        Date futureDate = new Date(System.currentTimeMillis() + 3600000);
        when(tokenService.getExpirationDateFromToken(validToken)).thenReturn(futureDate);

        // Add both tokens to the blacklist
        tokenBlacklistService.blacklistToken(expiredToken);
        tokenBlacklistService.blacklistToken(validToken);

        // When
        tokenBlacklistService.purgeExpiredTokens();

        // Then
        assertFalse(tokenBlacklistService.isTokenBlacklisted(expiredToken));
        assertTrue(tokenBlacklistService.isTokenBlacklisted(validToken));
    }
}