package com.lockbox.security.filter;

import com.lockbox.service.SecurityRateLimiterService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);

    @Autowired
    private SecurityRateLimiterService securityRateLimiterService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String uri = request.getRequestURI();

        // Apply rate limiting to auth endpoints only
        if (uri.startsWith("/api/auth") && !uri.equals("/api/auth/public-key") && !uri.equals("/api/auth/logout")) {
            // Get real client IP (handles proxies and direct connections)
            String clientIp = getClientIpAddress(request);
            logger.info("Rate limit check for {} from IP {}", uri, clientIp);

            if (securityRateLimiterService.isRateLimited(clientIp)) {
                logger.warn("Rate limit exceeded for {} from IP {}", uri, clientIp);
                securityRateLimiterService.applyConsistentTiming();
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                return;
            }
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            // Apply consistent timing for auth endpoints
            if (uri.startsWith("/api/auth")) {
                securityRateLimiterService.applyConsistentTiming();
            }
        }
    }

    /**
     * Extract the client IP address from the request, handling proxies correctly.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        // Check standard proxy headers first
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            // X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2...)
            // First IP is the original client
            return ip.split(",")[0].trim();
        }

        // Try other proxy headers
        ip = request.getHeader("Proxy-Client-IP");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip;
        }

        ip = request.getHeader("WL-Proxy-Client-IP");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip;
        }

        ip = request.getHeader("HTTP_CLIENT_IP");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip;
        }

        ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip;
        }

        // Finally, if no proxy detected, get direct client IP
        ip = request.getRemoteAddr();

        // Still handle IPv6 localhost
        if ("0:0:0:0:0:0:0:1".equals(ip)) {
            ip = "127.0.0.1";
        }

        return ip;
    }
}