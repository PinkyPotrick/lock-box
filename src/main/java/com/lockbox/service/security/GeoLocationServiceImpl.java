package com.lockbox.service.security;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

/**
 * Production implementation of GeoLocationService using MaxMind GeoIP2 database.
 */
@Service
public class GeoLocationServiceImpl implements GeoLocationService {

    private static final Logger logger = LoggerFactory.getLogger(GeoLocationServiceImpl.class);

    // Set of country codes considered high risk (example: North Korea, Iran, Syria, Sudan, Cuba)
    private static final Set<String> HIGH_RISK_COUNTRIES = new HashSet<>(Arrays.asList("KP", "IR", "SY", "SD", "CU"));

    // Earth's radius in kilometers
    private static final double EARTH_RADIUS_KM = 6371.0;

    @Value("${geoip.database.city.path:classpath:geoip/GeoLite2-City.mmdb}")
    private String geoIpCityDbPath;

    @Value("${geoip.database.country.path:classpath:geoip/GeoLite2-Country.mmdb}")
    private String geoIpCountryDbPath;

    private final ResourceLoader resourceLoader;

    private DatabaseReader cityReader;
    private DatabaseReader countryReader;

    public GeoLocationServiceImpl(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void initialize() {
        try {
            // Initialize City database reader
            Resource cityResource = resourceLoader.getResource(geoIpCityDbPath);
            File cityDbFile = cityResource.getFile();
            if (cityDbFile.exists()) {
                cityReader = new DatabaseReader.Builder(cityDbFile).build();
                logger.info("MaxMind GeoIP2 City database initialized from {}", geoIpCityDbPath);
            } else {
                logger.warn("MaxMind GeoIP2 City database not found at {}", geoIpCityDbPath);
            }

            // Initialize Country database reader
            Resource countryResource = resourceLoader.getResource(geoIpCountryDbPath);
            File countryDbFile = countryResource.getFile();
            if (countryDbFile.exists()) {
                countryReader = new DatabaseReader.Builder(countryDbFile).build();
                logger.info("MaxMind GeoIP2 Country database initialized from {}", geoIpCountryDbPath);
            } else {
                logger.warn("MaxMind GeoIP2 Country database not found at {}", geoIpCountryDbPath);
            }

        } catch (IOException e) {
            logger.error("Error initializing MaxMind GeoIP2 database: {}", e.getMessage());
        }
    }

    @PreDestroy
    public void cleanup() {
        try {
            if (cityReader != null) {
                cityReader.close();
            }
            if (countryReader != null) {
                countryReader.close();
            }
        } catch (IOException e) {
            logger.error("Error closing MaxMind GeoIP2 database reader: {}", e.getMessage());
        }
    }

    /**
     * Get the country code for an IP address
     * 
     * @param ipAddress - The IP address to look up
     * @return Optional country code (ISO two-letter code)
     */
    @Override
    public Optional<String> getCountryCode(String ipAddress) {
        if (!StringUtils.hasText(ipAddress) || isPrivateIpAddress(ipAddress)) {
            return Optional.empty();
        }

        try {
            if (countryReader != null) {
                InetAddress address = InetAddress.getByName(ipAddress);
                CountryResponse response = countryReader.country(address);
                return Optional.ofNullable(response.getCountry().getIsoCode());
            } else if (cityReader != null) {
                // Fall back to city database if country database isn't available
                InetAddress address = InetAddress.getByName(ipAddress);
                CityResponse response = cityReader.city(address);
                return Optional.ofNullable(response.getCountry().getIsoCode());
            }
        } catch (IOException | GeoIp2Exception e) {
            logger.debug("Unable to determine country code for IP {}: {}", ipAddress, e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Get the city for an IP address
     * 
     * @param ipAddress - The IP address to look up
     * @return Optional city name
     */
    @Override
    public Optional<String> getCity(String ipAddress) {
        if (!StringUtils.hasText(ipAddress) || isPrivateIpAddress(ipAddress)) {
            return Optional.empty();
        }

        try {
            if (cityReader != null) {
                InetAddress address = InetAddress.getByName(ipAddress);
                CityResponse response = cityReader.city(address);
                return Optional.ofNullable(response.getCity().getName());
            }
        } catch (IOException | GeoIp2Exception e) {
            logger.debug("Unable to determine city for IP {}: {}", ipAddress, e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Get the latitude and longitude for an IP address
     * 
     * @param ipAddress - The IP address to look up
     * @return Optional array [latitude, longitude] or empty if not found
     */
    @Override
    public Optional<double[]> getCoordinates(String ipAddress) {
        if (!StringUtils.hasText(ipAddress) || isPrivateIpAddress(ipAddress)) {
            return Optional.empty();
        }

        try {
            if (cityReader != null) {
                InetAddress address = InetAddress.getByName(ipAddress);
                CityResponse response = cityReader.city(address);

                Double latitude = response.getLocation().getLatitude();
                Double longitude = response.getLocation().getLongitude();

                if (latitude != null && longitude != null) {
                    return Optional.of(new double[] { latitude, longitude });
                }
            }
        } catch (IOException | GeoIp2Exception e) {
            logger.debug("Unable to determine coordinates for IP {}: {}", ipAddress, e.getMessage());
        }

        return Optional.empty();
    }

    /**
     * Calculate the distance between two sets of coordinates using the Haversine formula
     * 
     * @param lat1 - Latitude of first coordinate
     * @param lon1 - Longitude of first coordinate
     * @param lat2 - Latitude of second coordinate
     * @param lon2 - Longitude of second coordinate
     * @return Distance in kilometers
     */
    @Override
    public double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        // Haversine formula for calculating the distance between two points on a sphere
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);

        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(Math.toRadians(lat1))
                * Math.cos(Math.toRadians(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return EARTH_RADIUS_KM * c;
    }

    /**
     * Check if an IP address originates from a known high-risk country
     * 
     * @param ipAddress - The IP address to check
     * @return true if high risk, false otherwise
     */
    @Override
    public boolean isHighRiskCountry(String ipAddress) {
        if (!StringUtils.hasText(ipAddress) || isPrivateIpAddress(ipAddress)) {
            return false;
        }

        return getCountryCode(ipAddress).map(HIGH_RISK_COUNTRIES::contains).orElse(false);
    }

    /**
     * Checks if an IP address is a private/local network address
     * 
     * @param ipAddress IP address to check
     * @return true if it's a private/local address
     */
    private boolean isPrivateIpAddress(String ipAddress) {
        try {
            InetAddress address = InetAddress.getByName(ipAddress);
            return address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress();
        } catch (Exception e) {
            logger.debug("Error checking if IP is private: {}", ipAddress);
            return false;
        }
    }
}