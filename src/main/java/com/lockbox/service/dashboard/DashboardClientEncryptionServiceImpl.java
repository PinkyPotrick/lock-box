package com.lockbox.service.dashboard;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.dashboard.DashboardOverviewDTO;
import com.lockbox.dto.dashboard.DashboardOverviewResponseDTO;
import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryResponseDTO;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionServiceImpl;
import com.lockbox.utils.EncryptionUtils;

@Service
public class DashboardClientEncryptionServiceImpl implements DashboardClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(DashboardClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionServiceImpl genericEncryptionService;

    /**
     * Encrypts dashboard overview data for client response. Uses AES encryption to secure the overview data.
     * 
     * @param overviewDTO - The dashboard overview data to encrypt
     * @return Encrypted dashboard overview response ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public DashboardOverviewResponseDTO encryptDashboardOverview(DashboardOverviewDTO overviewDTO) throws Exception {
        if (overviewDTO == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        DashboardOverviewResponseDTO responseDTO = new DashboardOverviewResponseDTO();

        EncryptedDataAesCbc encryptedOverview = genericEncryptionService.encryptDTOWithAESCBC(overviewDTO,
                EncryptedDataAesCbc.class, aesKey);

        responseDTO.setEncryptedOverview(encryptedDataAesCbcMapper.toDto(encryptedOverview));
        responseDTO.setHelperAesKey(encryptedOverview.getAesKeyBase64());

        long endTime = System.currentTimeMillis();
        logger.info("Dashboard overview client response encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts login history data for client response. Uses AES encryption to secure the login history data.
     * 
     * @param loginHistoryData - The login history data to encrypt
     * @return Encrypted login history response ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public LoginHistoryResponseDTO encryptLoginHistory(LoginHistoryDTO loginHistoryData) throws Exception {
        if (loginHistoryData == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        LoginHistoryResponseDTO responseDTO = new LoginHistoryResponseDTO();

        EncryptedDataAesCbc encryptedData = genericEncryptionService.encryptDTOWithAESCBC(loginHistoryData,
                EncryptedDataAesCbc.class, aesKey);

        responseDTO.setEncryptedLoginHistory(encryptedDataAesCbcMapper.toDto(encryptedData));
        responseDTO.setHelperAesKey(encryptedData.getAesKeyBase64());

        long endTime = System.currentTimeMillis();
        logger.info("Login history client response encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }
}
