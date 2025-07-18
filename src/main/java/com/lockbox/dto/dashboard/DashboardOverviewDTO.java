package com.lockbox.dto.dashboard;

public class DashboardOverviewDTO {

    private int vaultCount;
    private int domainCount;
    private int credentialCount;
    private double loginSuccessRate;

    public DashboardOverviewDTO() {
    }

    public DashboardOverviewDTO(int vaultCount, int domainCount, int credentialCount) {
        this.vaultCount = vaultCount;
        this.domainCount = domainCount;
        this.credentialCount = credentialCount;
    }

    public int getVaultCount() {
        return vaultCount;
    }

    public void setVaultCount(int vaultCount) {
        this.vaultCount = vaultCount;
    }

    public int getDomainCount() {
        return domainCount;
    }

    public void setDomainCount(int domainCount) {
        this.domainCount = domainCount;
    }

    public int getCredentialCount() {
        return credentialCount;
    }

    public void setCredentialCount(int credentialCount) {
        this.credentialCount = credentialCount;
    }

    public double getLoginSuccessRate() {
        return loginSuccessRate;
    }

    public void setLoginSuccessRate(double loginSuccessRate) {
        this.loginSuccessRate = loginSuccessRate;
    }
}