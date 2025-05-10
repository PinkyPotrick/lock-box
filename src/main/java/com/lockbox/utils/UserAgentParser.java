package com.lockbox.utils;

/**
 * Utility class for parsing user agent strings.
 */
public class UserAgentParser {

    /**
     * Parses user agent string to extract browser and device information.
     * 
     * @param userAgent - The user agent string to parse
     * @return UserAgentInfo containing parsed browser and device information
     */
    public static UserAgentInfo parse(String userAgent) {
        String browser = "Unknown";
        String deviceType = "Unknown";

        if (userAgent == null) {
            return new UserAgentInfo(browser, deviceType);
        }

        // Determine browser
        if (userAgent.contains("Firefox")) {
            browser = "Firefox";
        } else if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            browser = "Chrome";
        } else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) {
            browser = "Safari";
        } else if (userAgent.contains("Edg")) {
            browser = "Edge";
        } else if (userAgent.contains("OPR") || userAgent.contains("Opera")) {
            browser = "Opera";
        } else if (userAgent.contains("MSIE") || userAgent.contains("Trident/")) {
            browser = "Internet Explorer";
        }

        // Determine device type
        if (userAgent.contains("Mobile") || (userAgent.contains("Android") && userAgent.contains("AppleWebKit"))) {
            deviceType = "Mobile";
        } else if (userAgent.contains("iPad") || userAgent.contains("Tablet")) {
            deviceType = "Tablet";
        } else {
            deviceType = "Desktop";
        }

        return new UserAgentInfo(browser, deviceType);
    }

    /**
     * Simple class to hold browser and device type information parsed from user agent.
     */
    public static class UserAgentInfo {
        private String browser;
        private String deviceType;

        public UserAgentInfo(String browser, String deviceType) {
            this.browser = browser;
            this.deviceType = deviceType;
        }

        public String getBrowser() {
            return browser;
        }

        public String getDeviceType() {
            return deviceType;
        }
    }
}