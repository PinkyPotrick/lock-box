package com.lockbox.model;

public class UserAgentInfo {
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
