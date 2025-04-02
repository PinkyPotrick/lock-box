package com.lockbox.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter that safely processes X-Forwarded-For and X-Real-IP headers to correctly identify client IP addresses when
 * behind a reverse proxy (like Nginx).
 * 
 * Security features:
 * 1. Only trusts headers from configured trusted proxies
 * 2. Validates IP format to prevent header injection
 * 3. Properly handles X-Forwarded-For chains by extracting original client IP
 * 4. Runs before security filters to ensure accurate IP for rate limiting
 * 
 * Configuration:
 * - security.ip.trusted-proxies: Comma-separated list of trusted proxy IPs (default: 127.0.0.1,::1)
 * - security.ip.verbose-logging: Enable detailed logging (default: false)
 * 
 * In production, this should be configured to only trust headers from known proxies.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // Run first, before Security filters
public class CustomIpFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(CustomIpFilter.class);

    // IPv4 and IPv6 validation patterns to prevent header injection attacks
    private static final Pattern IPV4_PATTERN = Pattern
            .compile("^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.(?!$)|$)){4}$");
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^::ffff:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");

    private final boolean isDevMode;
    private final Set<String> trustedProxies;
    private final boolean verboseLogging;

    /**
     * Initialize filter with configuration properties.
     *
     * @param environment          - Spring environment to detect dev mode
     * @param trustedProxiesString - Comma-separated list of trusted proxy IPs
     * @param verboseLogging       - Whether to enable detailed logging
     */
    public CustomIpFilter(Environment environment,
            @Value("${security.ip.trusted-proxies:127.0.0.1,::1}") String trustedProxiesString,
            @Value("${security.ip.verbose-logging:false}") boolean verboseLogging) {

        this.isDevMode = Arrays.asList(environment.getActiveProfiles()).contains("dev");
        this.verboseLogging = isDevMode || verboseLogging;

        // Parse trusted proxies from configuration
        this.trustedProxies = new HashSet<>();
        if (trustedProxiesString != null && !trustedProxiesString.isEmpty()) {
            for (String proxy : trustedProxiesString.split(",")) {
                this.trustedProxies.add(proxy.trim());
            }
        }

        logger.info("CustomIpFilter initialized. Dev mode: {}, Trusted proxies: {}", isDevMode, this.trustedProxies);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String remoteAddr = request.getRemoteAddr();

            if (verboseLogging) {
                logger.debug("Processing request URL: {}", httpRequest.getRequestURL());
                logger.debug("Remote addr: {}", remoteAddr);
            }

            // Only process forwarded headers if the request comes from a trusted proxy
            boolean isTrustedProxy = trustedProxies.contains(remoteAddr) || isDevMode;

            if (isTrustedProxy) {
                String forwardedFor = httpRequest.getHeader("X-Forwarded-For");
                String realIp = httpRequest.getHeader("X-Real-IP");

                if (verboseLogging) {
                    logger.debug("X-Forwarded-For: {}", forwardedFor);
                    logger.debug("X-Real-IP: {}", realIp);
                }

                boolean hasValidHeaders = (forwardedFor != null && isValidIp(parseClientIpFromXFF(forwardedFor)))
                        || (realIp != null && isValidIp(realIp));

                if (hasValidHeaders) {
                    request = new CustomHttpServletRequestWrapper((HttpServletRequest) request);
                    if (verboseLogging) {
                        logger.debug("Request wrapped, new remote addr: {}", request.getRemoteAddr());
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Extracts the original client IP from X-Forwarded-For header. The leftmost IP is the original client, followed by
     * any intermediary proxies.
     */
    private String parseClientIpFromXFF(String forwardedFor) {
        if (forwardedFor == null || forwardedFor.isEmpty()) {
            return null;
        }

        // The leftmost IP is the client IP
        return forwardedFor.split(",")[0].trim();
    }

    /**
     * Validates that a string is a valid IPv4 or IPv6 address. This prevents header injection attacks through malformed
     * IPs.
     */
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        return IPV4_PATTERN.matcher(ip).matches() || IPV6_PATTERN.matcher(ip).matches();
    }

    /**
     * Request wrapper that overrides getRemoteAddr() to return the forwarded IP. This ensures that all Spring Security
     * components and filters see the correct client IP.
     */
    private static class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {
        public CustomHttpServletRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getRemoteAddr() {
            String forwardedFor = getHeader("X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isEmpty()) {
                // The leftmost IP is the client IP
                return forwardedFor.split(",")[0].trim();
            }

            String realIp = getHeader("X-Real-IP");
            if (realIp != null && !realIp.isEmpty()) {
                return realIp;
            }

            return super.getRemoteAddr();
        }
    }
}