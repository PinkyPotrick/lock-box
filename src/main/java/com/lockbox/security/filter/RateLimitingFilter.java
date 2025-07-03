package com.lockbox.security.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lockbox.service.SecurityRateLimiterService;
import com.lockbox.utils.RequestUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);

    // Define sensitive endpoints that should be rate limited
    private static final Set<String> RATE_LIMITED_ENDPOINTS = new HashSet<>(Arrays.asList( //
            "/api/auth/login", //
            "/api/auth/register", //
            "/api/auth/srp-init", //
            "/api/auth/verify-totp", //
            "/api/auth/verify-operation-totp", //
            "/api/users/password-change/init", //
            "/api/users/password-change/complete" //
    ));

    // Define endpoints that are exempt from rate limiting
    private static final Set<String> WHITE_LIST_ENDPOINTS = new HashSet<>(Arrays.asList( //
            "/api/auth/public-key", //
            "/api/auth/logout" //
    ));

    @Autowired
    private SecurityRateLimiterService securityRateLimiterService;

    // Simple IP rate limiting - 100 requests per minute per IP
    private static final int MAX_REQUESTS_PER_MINUTE = 100;
    private static final ConcurrentHashMap<String, IpRateLimit> ipRateLimits = new ConcurrentHashMap<>();

    // Simple rate limit tracking per IP
    private static class IpRateLimit {
        private final AtomicInteger requestCount = new AtomicInteger(0);
        private volatile long windowStartTime = System.currentTimeMillis();

        public boolean isRateLimited() {
            long currentTime = System.currentTimeMillis();

            // Reset window if more than 1 minute has passed
            if (currentTime - windowStartTime > 60000) {
                windowStartTime = currentTime;
                requestCount.set(0);
            }
            
            // Check if over limit
            return requestCount.incrementAndGet() > MAX_REQUESTS_PER_MINUTE;
        }

        public int getCurrentCount() {
            return requestCount.get();
        }
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String uri = request.getRequestURI();
        String clientIp = RequestUtils.getClientIpAddressEnhanced(request);

        // Global IP rate limiting for all API endpoints
        if (uri.startsWith("/api/")) {
            IpRateLimit rateLimit = ipRateLimits.computeIfAbsent(clientIp, k -> new IpRateLimit());
            
            if (rateLimit.isRateLimited()) {
                logger.warn("GLOBAL RATE LIMIT EXCEEDED for IP {} - {} requests/minute", 
                           clientIp, rateLimit.getCurrentCount());
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write(
                    "{\"error\":\"Rate limit exceeded\",\"message\":\"Too many requests from this IP\"}"
                );
                return;
            }
        }

        // Apply additional rate limiting to sensitive endpoints
        if (shouldApplyRateLimit(uri)) {
            logger.info("Rate limit check for {} from IP {}", uri, clientIp);

            if (securityRateLimiterService.isRateLimited(clientIp)) {
                logger.warn("SENSITIVE ENDPOINT rate limit exceeded for {} from IP {}", uri, clientIp);
                securityRateLimiterService.applyConsistentTiming();
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                return;
            }
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            // Apply consistent timing for auth endpoints and password change endpoints
            if (uri.startsWith("/api/auth") || uri.contains("/password-change/")) {
                securityRateLimiterService.applyConsistentTiming();
            }
        }
    }

    /**
     * Determines whether rate limiting should be applied to the given URI.
     * 
     * @param uri - The request URI
     * @return true if rate limiting should be applied, false otherwise
     */
    private boolean shouldApplyRateLimit(String uri) {
        // Check if the URI exactly matches any of our explicitly rate limited endpoints
        if (RATE_LIMITED_ENDPOINTS.contains(uri)) {
            return true;
        }

        // Check if the URI starts with /api/auth but is not in the white list
        if (uri.startsWith("/api/auth") && !WHITE_LIST_ENDPOINTS.contains(uri)) {
            return true;
        }

        return false;
    }

    // Cleanup method to prevent memory leaks
    public static void cleanupOldEntries() {
        long currentTime = System.currentTimeMillis();
        ipRateLimits.entrySet().removeIf(entry -> {
            long timeSinceLastWindow = currentTime - entry.getValue().windowStartTime;
            return timeSinceLastWindow > 300000; // Remove entries older than 5 minutes
        });
    }
}