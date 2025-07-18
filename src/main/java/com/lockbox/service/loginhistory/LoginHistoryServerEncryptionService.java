package com.lockbox.service.loginhistory;

import com.lockbox.model.LoginHistory;

public interface LoginHistoryServerEncryptionService {

    LoginHistory encryptServerData(LoginHistory loginHistory) throws Exception;

    LoginHistory decryptServerData(LoginHistory loginHistory) throws Exception;
}