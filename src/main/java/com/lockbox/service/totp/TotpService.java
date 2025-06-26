package com.lockbox.service.totp;

import com.lockbox.dto.totp.TotpSetupDTO;

public interface TotpService {

    TotpSetupDTO generateTotpSecret(String userId) throws Exception;

    boolean verifyTotpSetup(String userId, String code) throws Exception;

    boolean disableTotp(String userId) throws Exception;

    boolean verifyTotpAuthentication(String userId, String code) throws Exception;
    
    void resetFailedAttempts(String userId, boolean completeReset);
}