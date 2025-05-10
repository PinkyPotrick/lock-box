package com.lockbox.dto.loginhistory;

import java.util.List;

public class LoginHistoryListResponseDTO {

    private List<LoginHistoryResponseDTO> loginHistories;
    private long totalCount;
    private int successCount;
    private int failureCount;

    public LoginHistoryListResponseDTO() {
    }

    public List<LoginHistoryResponseDTO> getLoginHistories() {
        return loginHistories;
    }

    public void setLoginHistories(List<LoginHistoryResponseDTO> loginHistories) {
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