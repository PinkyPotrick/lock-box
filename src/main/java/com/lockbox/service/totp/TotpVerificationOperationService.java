package com.lockbox.service.totp;

public interface TotpVerificationOperationService {

    boolean verifyOperationTotp(String userId, String code, String operation) throws Exception;

    boolean hasValidVerification();

    void invalidateVerification();
}
