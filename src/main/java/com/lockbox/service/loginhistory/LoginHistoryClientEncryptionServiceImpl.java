package com.lockbox.service.loginhistory;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryResponseDTO;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link LoginHistoryClientEncryptionService} interface, responsible for encrypting login history
 * data for secure transmission between client and server.
 */
@Service
public class LoginHistoryClientEncryptionServiceImpl implements LoginHistoryClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(LoginHistoryClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts a single {@link LoginHistoryDTO} for client response. Uses AES encryption to secure the login history
     * data.
     * 
     * @param loginHistoryDTO - The login history data to encrypt
     * @return Encrypted {@link LoginHistoryResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public LoginHistoryResponseDTO encryptLoginHistoryForClient(LoginHistoryDTO loginHistoryDTO) throws Exception {
        if (loginHistoryDTO == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        LoginHistoryResponseDTO responseDTO = new LoginHistoryResponseDTO();

        EncryptedDataAesCbc encryptedLoginHistory = genericEncryptionService.encryptDTOWithAESCBC(loginHistoryDTO,
                EncryptedDataAesCbc.class, aesKey);

        responseDTO.setEncryptedLoginHistory(encryptedDataAesCbcMapper.toDto(encryptedLoginHistory));
        responseDTO.setHelperAesKey(encryptedLoginHistory.getAesKeyBase64());

        long endTime = System.currentTimeMillis();
        logger.info("Login history client response encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts a list of {@link LoginHistoryDTOs} for client response. Preserves the list structure while encrypting
     * individual items.
     * 
     * @param listDTO - The list of login history data to encrypt
     * @return Encrypted {@link LoginHistoryListResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public LoginHistoryListResponseDTO encryptLoginHistoryListForClient(LoginHistoryListDTO listDTO) throws Exception {
        if (listDTO == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        LoginHistoryListResponseDTO responseDTO = new LoginHistoryListResponseDTO();
        responseDTO.setTotalCount(listDTO.getTotalCount());
        responseDTO.setSuccessCount(listDTO.getSuccessCount());
        responseDTO.setFailureCount(listDTO.getFailureCount());
        responseDTO.setLoginHistories(encryptLoginHistoryListItemsForClient(listDTO.getLoginHistories()));

        long endTime = System.currentTimeMillis();
        logger.info("Login history client list encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts individual {@link LoginHistoryDTOs} in a list for client response.
     * 
     * @param loginHistoryDTOs - The list of login history data to encrypt
     * @return List of individually encrypted {@link LoginHistoryResponseDTOs}
     * @throws Exception If encryption fails
     */
    @Override
    public List<LoginHistoryResponseDTO> encryptLoginHistoryListItemsForClient(List<LoginHistoryDTO> loginHistoryDTOs)
            throws Exception {
        if (loginHistoryDTOs == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        List<LoginHistoryResponseDTO> encryptedList = new ArrayList<>();
        for (LoginHistoryDTO dto : loginHistoryDTOs) {
            encryptedList.add(encryptLoginHistoryForClient(dto));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Login history client list items encryption process completed in {} ms", endTime - startTime);

        return encryptedList;
    }
}