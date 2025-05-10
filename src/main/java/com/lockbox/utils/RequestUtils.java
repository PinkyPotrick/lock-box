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
}