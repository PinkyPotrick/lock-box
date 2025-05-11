package com.lockbox.service.domain;

import com.lockbox.model.Domain;

public interface DomainServerEncryptionService {

    Domain encryptServerData(Domain domain) throws Exception;

    Domain decryptServerData(Domain domain) throws Exception;
}