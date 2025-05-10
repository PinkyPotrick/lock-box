package com.lockbox.service.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.loginhistory.LoginHistoryService;
import com.lockbox.service.token.TokenBlacklistService;
import com.lockbox.utils.RequestUtils;
import com.lockbox.utils.SecurityUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private SecurityUtils securityUtils;

    private final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    @Override
    public void logout() {
        try {
            // Extract token using SecurityUtils - completely request-independent
            String token = securityUtils.getCurrentToken();

            // Add the token to blacklist to prevent reuse
            tokenBlacklistService.blacklistToken(token);

            // Get user info
            String userId = securityUtils.getCurrentUserId();
            logger.info("User logged out: {}", userId);

            // Clear encryption keys from session
            sessionKeyStore.clearUserKeys();

            // Invalidate the session from the current request context
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpSession session = attributes.getRequest().getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            }
        } catch (Exception e) {
            logger.warn("Error during logout: {}", e.getMessage());
        }
    }

    /**
     * Processes a successful authentication and records it in the login history.
     * 
     * @param userId The ID of the authenticated user
     * @throws Exception If recording fails
     */
    @Override
    public void recordSuccessfulAuthentication(String userId) throws Exception {
        // Get IP address and user agent
        String ipAddress = RequestUtils.getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Record successful login
        loginHistoryService.recordSuccessfulLogin(userId, ipAddress, userAgent);
    }

    /**
     * Processes a failed authentication and records it in the login history.
     * 
     * @param userId The attempted user ID
     * @param reason The reason for the authentication failure
     * @throws Exception If recording fails
     */
    @Override
    public void recordFailedAuthentication(String userId, String reason) throws Exception {
        // Get IP address and user agent
        String ipAddress = RequestUtils.getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Record failed login
        loginHistoryService.recordFailedLogin(userId, ipAddress, userAgent, reason);
    }
}
