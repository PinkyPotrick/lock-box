package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.service.dashboard.DashboardService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping("/overview")
    public ResponseEntityDTO<DashboardOverviewResponseDTO> getDashboardOverview() {
        try {
            String userId = securityUtils.getCurrentUserId();
            DashboardOverviewResponseDTO response = dashboardService.getDashboardOverview(userId);
            ResponseEntityBuilder<DashboardOverviewResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(response).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Dashboard overview retrieval failed")
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/login-history")
    public ResponseEntityDTO<LoginHistoryListResponseDTO> getLoginHistory() {
        try {
            String userId = securityUtils.getCurrentUserId();
            LoginHistoryListResponseDTO response = dashboardService.getLoginHistory(userId,
                    AppConstants.LOGIN_HISTORY_LIMIT);
            ResponseEntityBuilder<LoginHistoryListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(response).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Login history retrieval failed").throwInternalServerErrorException();
            return null;
        }
    }
}