package com.lockbox.service.security;

import java.util.Optional;

public interface GeoLocationService {

    Optional<String> getCountryCode(String ipAddress);

    Optional<String> getCity(String ipAddress);

    Optional<double[]> getCoordinates(String ipAddress);

    double calculateDistance(double lat1, double lon1, double lat2, double lon2);

    boolean isHighRiskCountry(String ipAddress);
}