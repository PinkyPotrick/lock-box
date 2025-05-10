package com.lockbox.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.lockbox.dto.domain.DomainRequestDTO;

import java.net.URI;
import java.net.URISyntaxException;

@Component
public class DomainValidator {

    private final Logger logger = LoggerFactory.getLogger(DomainValidator.class);

    /**
     * Validate a domain request DTO
     * 
     * @param requestDTO The domain request to validate
     * @throws Exception If validation fails
     */
    public void validateDomainRequest(DomainRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Domain request cannot be null");
            throw new Exception("Domain request cannot be null");
        }

        if (requestDTO.getName() == null || requestDTO.getName().trim().isEmpty()) {
            logger.error("Domain name is required");
            throw new Exception("Domain name is required");
        }

        if (requestDTO.getName().length() > 100) {
            logger.error("Domain name cannot exceed 100 characters");
            throw new Exception("Domain name cannot exceed 100 characters");
        }

        if (requestDTO.getUrl() != null) {
            try {
                // Try to parse and normalize the URL to validate it
                normalizeUrl(requestDTO.getUrl());
            } catch (Exception e) {
                logger.error("Invalid URL format: {}", e.getMessage());
                throw new Exception("Invalid URL format");
            }
        }

        if (requestDTO.getNotes() != null && requestDTO.getNotes().length() > 500) {
            logger.error("Domain notes cannot exceed 500 characters");
            throw new Exception("Domain notes cannot exceed 500 characters");
        }
    }

    /**
     * Normalize a URL by removing protocol, www prefix, and trailing slashes
     * 
     * @param url The URL to normalize
     * @return The normalized URL
     * @throws Exception If the URL is invalid
     */
    public String normalizeUrl(String url) throws Exception {
        if (url == null || url.trim().isEmpty()) {
            return "";
        }

        // Ensure URL has a protocol for parsing
        String urlWithProtocol = url;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            urlWithProtocol = "https://" + url;
        }

        try {
            URI uri = new URI(urlWithProtocol);
            String host = uri.getHost();

            if (host == null) {
                throw new Exception("Invalid URL");
            }

            // Remove www. prefix if present
            if (host.startsWith("www.")) {
                host = host.substring(4);
            }

            // Include path if present
            String path = uri.getPath();
            if (path != null && !path.isEmpty() && !path.equals("/")) {
                // Remove trailing slash
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                }
                return host + path;
            }

            return host;
        } catch (URISyntaxException e) {
            logger.error("Error normalizing URL: {}", e.getMessage());
            throw new Exception("Invalid URL format");
        }
    }
}