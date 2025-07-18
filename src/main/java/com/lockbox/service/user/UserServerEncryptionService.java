package com.lockbox.service.user;

import com.lockbox.model.User;

public interface UserServerEncryptionService {
    User encryptServerData(User user) throws Exception;

    User decryptServerData(User user) throws Exception;
}