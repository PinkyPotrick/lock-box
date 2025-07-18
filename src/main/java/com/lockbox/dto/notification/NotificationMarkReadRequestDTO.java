package com.lockbox.dto.notification;

import java.util.List;

public class NotificationMarkReadRequestDTO {

    private List<String> notificationIds;
    private boolean markAsRead;

    public NotificationMarkReadRequestDTO() {
    }

    public List<String> getNotificationIds() {
        return notificationIds;
    }

    public void setNotificationIds(List<String> notificationIds) {
        this.notificationIds = notificationIds;
    }

    public boolean isMarkAsRead() {
        return markAsRead;
    }

    public void setMarkAsRead(boolean markAsRead) {
        this.markAsRead = markAsRead;
    }
}