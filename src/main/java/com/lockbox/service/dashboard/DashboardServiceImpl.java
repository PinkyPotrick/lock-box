package com.lockbox.service.dashboard;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.dashboard.DashboardOverviewDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryMapper;
import com.lockbox.model.LoginHistory;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.repository.DomainRepository;
import com.lockbox.repository.LoginHistoryRepository;
import com.lockbox.repository.VaultRepository;
import com.lockbox.service.loginhistory.LoginHistoryClientEncryptionService;
import com.lockbox.service.loginhistory.LoginHistoryServerEncryptionService;
import com.lockbox.service.loginhistory.LoginHistoryService;

/**
 * Implementation of the {@link DashboardService} interface. Provides methods for retrieving and processing dashboard
 * data.
 */
@Service
public class DashboardServiceImpl implements DashboardService {

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

    /**
     * Gets dashboard overview data for a user.
     * 
     * @param userId - The ID of the user
     * @return Encrypted dashboard overview response
     * @throws Exception If retrieval fails
     */
    @Override
    public DashboardOverviewResponseDTO getDashboardOverview(String userId) throws Exception {
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

        // Encrypt and return data
        return dashboardClientEncryptionService.encryptDashboardOverview(overviewData);
    }

    /**
     * Gets login history data for a user.
     * 
     * @param userId - The ID of the user
     * @param limit  - Maximum number of entries to return (0 for all)
     * @return Encrypted login history list response
     * @throws Exception If retrieval fails
     */
    @Override
    public LoginHistoryListResponseDTO getLoginHistory(String userId, int limit) throws Exception {
        // Get login history entries
        List<LoginHistory> encryptedLoginHistories;
        if (limit > 0) {
            encryptedLoginHistories = loginHistoryRepository.findLatestByUserId(userId, limit);
        } else {
            encryptedLoginHistories = loginHistoryRepository.findByUserIdOrderByLoginTimestampDesc(userId);
        }

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