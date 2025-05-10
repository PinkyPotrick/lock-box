package com.lockbox.dto.loginhistory;

import java.util.List;

public class LoginHistoryListDTO {

    private List<LoginHistoryDTO> loginHistories;
    private long totalCount;
    private int successCount;
    private int failureCount;

    public LoginHistoryListDTO() {
    }

    public LoginHistoryListDTO(List<LoginHistoryDTO> loginHistories, long totalCount, int successCount,
            int failureCount) {
        this.loginHistories = loginHistories;
        this.totalCount = totalCount;
        this.successCount = successCount;
        this.failureCount = failureCount;
    }

    public List<LoginHistoryDTO> getLoginHistories() {
        return loginHistories;
    }

    public void setLoginHistories(List<LoginHistoryDTO> loginHistories) {
        this.loginHistories = loginHistories;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(long totalCount) {
        this.totalCount = totalCount;
    }

    public int getSuccessCount() {
        return successCount;
    }

    public void setSuccessCount(int successCount) {
        this.successCount = successCount;
    }

    public int getFailureCount() {
        return failureCount;
    }

    public void setFailureCount(int failureCount) {
        this.failureCount = failureCount;
    }
}