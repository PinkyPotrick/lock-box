package com.lockbox.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.service.dashboard.DashboardService;
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
            return new ResponseEntityBuilder<DashboardOverviewResponseDTO>().setData(response)
                    .setMessage("Dashboard overview retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Dashboard overview retrieval failed");
        }
    }

    @GetMapping("/login-history")
    public ResponseEntityDTO<LoginHistoryListResponseDTO> getLoginHistory(
            @RequestParam(name = "days", defaultValue = "30") int days) {
        try {
            String userId = securityUtils.getCurrentUserId();
            LoginHistoryListResponseDTO response = dashboardService.getLoginHistory(userId, days);
            return new ResponseEntityBuilder<LoginHistoryListResponseDTO>().setData(response)
                    .setMessage("Login history retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Login history retrieval failed");
        }
    }
}