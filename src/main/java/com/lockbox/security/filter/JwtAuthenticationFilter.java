package com.lockbox.security.filter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lockbox.service.token.TokenBlacklistService;
import com.lockbox.service.token.TokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Skip authentication for public endpoints
        String uri = request.getRequestURI();
        if (shouldSkipAuthentication(uri)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract token from request
        String token = extractToken(request);

        if (token == null) {
            logger.warn("No token found in request to {}", uri);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return;
        }

        try {
            // Check if token is blacklisted
            if (tokenBlacklistService.isTokenBlacklisted(token)) {
                logger.warn("Attempt to use blacklisted token for {}", uri);
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write("Token has been invalidated");
                return;
            }

            // Validate token
            if (!tokenService.validateToken(token)) {
                logger.warn("Invalid or expired token for {}", uri);
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }

            // If we get here, token is valid
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            logger.error("Error processing authentication token: {}", e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }
    }

    /**
     * Extract JWT token from Authorization header
     * 
     * @param request The HTTP request
     * @return The token string or null if not found
     */
    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Check if the request URI should skip authentication
     * 
     * @param uri The request URI
     * @return true if authentication should be skipped, false otherwise
     */
    private boolean shouldSkipAuthentication(String uri) {
        // Skip authentication for login, registration and public endpoints
        return uri.startsWith("/api/auth/public-key") || //
                uri.startsWith("/api/auth/register") || //
                uri.startsWith("/api/auth/srp-params") || //
                uri.startsWith("/api/auth/srp-authenticate") || //
                uri.startsWith("/api/auth/verify-totp") || //
                uri.equals("/api/health") || //
                uri.startsWith("/api/docs") || //
                uri.startsWith("/swagger-ui");
    }
}