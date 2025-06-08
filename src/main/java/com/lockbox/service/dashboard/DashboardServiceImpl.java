package com.lockbox.service.dashboard;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.dashboard.DashboardOverviewDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryMapper;
import com.lockbox.model.LoginHistory;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.repository.DomainRepository;
import com.lockbox.repository.LoginHistoryRepository;
import com.lockbox.repository.VaultRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.loginhistory.LoginHistoryClientEncryptionService;
import com.lockbox.service.loginhistory.LoginHistoryServerEncryptionService;
import com.lockbox.service.loginhistory.LoginHistoryService;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.LogMessages;

/**
 * Implementation of the {@link DashboardService} interface. Provides methods for retrieving and processing dashboard
 * data.
 */
@Service
public class DashboardServiceImpl implements DashboardService {

    private final Logger logger = LoggerFactory.getLogger(DashboardServiceImpl.class);

    @Autowired
    private VaultRepository vaultRepository;

    @Autowired
    private DomainRepository domainRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    @Autowired
    private LoginHistoryServerEncryptionService loginHistoryServerEncryptionService;

    @Autowired
    private LoginHistoryClientEncryptionService loginHistoryClientEncryptionService;

    @Autowired
    private LoginHistoryMapper loginHistoryMapper;

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private DashboardClientEncryptionService dashboardClientEncryptionService;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Gets dashboard overview data for a user.
     * 
     * @param userId - The ID of the user
     * @return Encrypted dashboard overview response
     * @throws Exception If retrieval fails
     */
    @Override
    public DashboardOverviewResponseDTO getDashboardOverview(String userId) throws Exception {
        try {
            // Count vaults, domains, and credentials for this user
            int vaultCount = vaultRepository.countByUserId(userId);
            int domainCount = domainRepository.countByUserId(userId);
            int credentialCount = credentialRepository.countByUserId(userId);

            // Get login success rate
            double loginSuccessRate = loginHistoryService.getLoginSuccessRate(userId);

            // Create data transfer object
            DashboardOverviewDTO overviewData = new DashboardOverviewDTO();
            overviewData.setVaultCount(vaultCount);
            overviewData.setDomainCount(domainCount);
            overviewData.setCredentialCount(credentialCount);
            overviewData.setLoginSuccessRate(loginSuccessRate);

            // Log dashboard view
            try {
                auditLogService.logUserAction(userId, ActionType.USER_LOGIN, OperationType.READ, LogLevel.INFO, null,
                        "Dashboard", ActionStatus.SUCCESS, null, "User viewed dashboard overview");
            } catch (Exception e) {
                logger.error(LogMessages.AUDIT_LOG_FAILED, e.getMessage());
            }

            // Encrypt and return data
            return dashboardClientEncryptionService.encryptDashboardOverview(overviewData);
        } catch (Exception e) {
            // Log failure
            try {
                auditLogService.logUserAction(userId, ActionType.USER_LOGIN, OperationType.READ, LogLevel.ERROR, null,
                        "Dashboard", ActionStatus.FAILURE, e.getMessage(), "Failed to retrieve dashboard overview");
            } catch (Exception ex) {
                logger.error(LogMessages.AUDIT_LOG_FAILED, ex.getMessage());
            }
            throw e;
        }
    }

    /**
     * Gets login history data for a user filtered by number of days in the past.
     * 
     * @param userId - The ID of the user
     * @param days   - Number of days in the past to retrieve login history for (7, 30, or 90)
     * @return Encrypted login history list response
     * @throws Exception If retrieval fails
     */
    @Override
    public LoginHistoryListResponseDTO getLoginHistory(String userId, int days) throws Exception {
        // Validate days parameter - only allow 7, 30, or 90; default to 30 if invalid
        if (days != 7 && days != 30 && days != 90) {
            days = 30;
        }

        // Calculate the start date based on days parameter
        LocalDateTime startDate = LocalDateTime.now().minusDays(days);

        // Get login history entries within the date range
        List<LoginHistory> encryptedLoginHistories = loginHistoryRepository
                .findByLoginTimestampAfterAndUserIdOrderByLoginTimestampDesc(startDate, userId);

        // Decrypt entries for internal processing
        List<LoginHistory> decryptedLoginHistories = new ArrayList<>();
        for (LoginHistory encryptedLoginHistory : encryptedLoginHistories) {
            decryptedLoginHistories.add(loginHistoryServerEncryptionService.decryptServerData(encryptedLoginHistory));
        }

        // Convert to DTOs
        List<LoginHistoryDTO> loginHistoryDTOs = loginHistoryMapper.toDTOList(decryptedLoginHistories);

        // Get statistics
        int totalCount = loginHistoryRepository.countByUserId(userId);
        int successCount = loginHistoryRepository.countByUserIdAndSuccess(userId, true);
        int failureCount = loginHistoryRepository.countByUserIdAndSuccess(userId, false);

        // Create list DTO
        LoginHistoryListDTO listDTO = loginHistoryMapper.toListDTO(loginHistoryDTOs, totalCount, successCount,
                failureCount);

        // Encrypt for client and return
        return loginHistoryClientEncryptionService.encryptLoginHistoryListForClient(listDTO);
    }
}