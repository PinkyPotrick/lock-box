package com.lockbox.utils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility class for HTTP request operations.
 */
public class RequestUtils {

    private static final String[] IP_HEADERS = { //
            "X-Forwarded-For", //
            "Proxy-Client-IP", //
            "WL-Proxy-Client-IP", //
            "HTTP_X_FORWARDED_FOR", //
            "HTTP_X_FORWARDED", //
            "HTTP_X_CLUSTER_CLIENT_IP", //
            "HTTP_CLIENT_IP", //
            "HTTP_FORWARDED_FOR", //
            "HTTP_FORWARDED", //
            "HTTP_VIA", //
            "REMOTE_ADDR" //
    };

    /**
     * Gets the client's real IP address from request headers. Checks various header fields to determine the actual
     * client IP address, accounting for proxies and load balancers.
     * 
     * @param request The HTTP request
     * @return The client's IP address
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        for (String header : IP_HEADERS) {
            String ipFromHeader = request.getHeader(header);
            if (ipFromHeader != null && ipFromHeader.length() != 0 && !"unknown".equalsIgnoreCase(ipFromHeader)) {
                // X-Forwarded-For can contain multiple IPs, first one is the client
                String[] parts = ipFromHeader.split(",");
                return parts[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    /**
     * Enhanced IP address extraction with additional proxy headers and validation.
     * Use this for security-sensitive operations like session binding.
     * 
     * @param request The HTTP request
     * @return The client's IP address with enhanced detection
     */
    public static String getClientIpAddressEnhanced(HttpServletRequest request) {
        // Check standard proxy headers first
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip.split(",")[0].trim();
        }

        ip = request.getHeader("X-Real-IP");
        if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
            return ip;
        }

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

        ip = request.getRemoteAddr();
        if ("0:0:0:0:0:0:0:1".equals(ip)) {
            ip = "127.0.0.1";
        }

        return ip;
    }
}