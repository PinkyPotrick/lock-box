package com.lockbox.service.credential;

import com.lockbox.model.Credential;

public interface CredentialServerEncryptionService {

    Credential encryptServerData(Credential credential) throws Exception;

    Credential decryptServerData(Credential credential) throws Exception;
}