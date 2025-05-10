package com.lockbox.service.loginhistory;

import java.util.List;

import com.lockbox.dto.loginhistory.LoginHistoryDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListDTO;
import com.lockbox.dto.loginhistory.LoginHistoryListResponseDTO;
import com.lockbox.dto.loginhistory.LoginHistoryResponseDTO;

public interface LoginHistoryClientEncryptionService {

    LoginHistoryResponseDTO encryptLoginHistoryForClient(LoginHistoryDTO loginHistoryDTO) throws Exception;

    LoginHistoryListResponseDTO encryptLoginHistoryListForClient(LoginHistoryListDTO listDTO) throws Exception;

    List<LoginHistoryResponseDTO> encryptLoginHistoryListItemsForClient(List<LoginHistoryDTO> loginHistoryDTOs)
            throws Exception;
}