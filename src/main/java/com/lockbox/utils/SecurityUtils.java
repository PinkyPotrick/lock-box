package com.lockbox.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.lockbox.service.token.TokenService;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class SecurityUtils {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AdminUtils adminUtils;

    /**
     * Get the current authenticated user's ID from the JWT token
     * 
     * @return The user ID
     * @throws Exception If the user ID cannot be determined
     */
    public String getCurrentUserId() throws Exception {
        String token = getCurrentToken();
        return tokenService.getUserIdFromToken(token);
    }

    /**
     * Get the current authenticated username from the JWT token
     * 
     * @return The username
     * @throws Exception If the username cannot be determined
     */
    public String getCurrentUsername() throws Exception {
        String token = getCurrentToken();
        return tokenService.getUsernameFromToken(token);
    }

    /**
     * Get the current JWT token from the request context
     * 
     * @return The JWT token
     * @throws Exception If the token cannot be determined
     */
    public String getCurrentToken() throws Exception {
        HttpServletRequest request = getCurrentRequest();
        String token = extractToken(request);
        if (token == null) {
            throw new Exception("Authorization token not found");
        }
        return token;
    }

    /**
     * Extract token from the current request
     * 
     * @return The JWT token string or null if not found
     * @throws Exception If request attributes are not available
     */
    public String extractCurrentToken() throws Exception {
        return extractToken(getCurrentRequest());
    }

    /**
     * Extract token from request
     * 
     * @param request The HTTP request
     * @return The JWT token string or null if not found
     */
    public String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.substring(7);
    }

    /**
     * Get the current HTTP request from RequestContextHolder
     * 
     * @return The current request
     * @throws Exception If request attributes are not available
     */
    private HttpServletRequest getCurrentRequest() throws Exception {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            throw new Exception("Request attributes not available");
        }
        return attributes.getRequest();
    }

    /**
     * Check if current user is an admin and throw exception if not
     * 
     * @throws Exception
     */
    public void ensureAdmin() throws Exception {
        String userId = getCurrentUserId();
        String username = getCurrentUsername();

        if (!adminUtils.isAdminById(userId) || !adminUtils.isAdmin(username)) {
            throw new SecurityException("Admin privileges required for this operation");
        }
    }

    /**
     * Check if current user is an admin
     * 
     * @return true if user is an admin, false otherwise
     */
    public boolean isAdmin() {
        try {
            String userId = getCurrentUserId();
            String username = getCurrentUsername();

            return adminUtils.isAdminById(userId) && adminUtils.isAdmin(username);
        } catch (Exception e) {
            return false;
        }
    }
}