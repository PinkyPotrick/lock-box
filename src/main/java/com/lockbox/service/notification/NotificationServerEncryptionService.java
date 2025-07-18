package com.lockbox.service.notification;

import com.lockbox.model.Notification;

public interface NotificationServerEncryptionService {

    Notification encryptServerData(Notification notification) throws Exception;

    Notification decryptServerData(Notification notification) throws Exception;
}