package com.lockbox.service.dashboard;

import com.lockbox.dto.dashboard.DashboardOverviewDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryResponseDTO;

public interface DashboardClientEncryptionService {

    DashboardOverviewResponseDTO encryptDashboardOverview(DashboardOverviewDTO overviewDTO) throws Exception;

    public LoginHistoryResponseDTO encryptLoginHistory(LoginHistoryDTO loginHistoryData) throws Exception;
}