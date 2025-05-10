package com.lockbox.service.dashboard;

import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;

public interface DashboardService {

    DashboardOverviewResponseDTO getDashboardOverview(String userId) throws Exception;

    LoginHistoryListResponseDTO getLoginHistory(String userId, int limit) throws Exception;
}