package com.lockbox.dto.notification;

public class NotificationUnreadCountResponseDTO {

    private int unreadCount;

    public NotificationUnreadCountResponseDTO() {
    }

    public NotificationUnreadCountResponseDTO(int unreadCount) {
        this.unreadCount = unreadCount;
    }

    public int getUnreadCount() {
        return unreadCount;
    }

    public void setUnreadCount(int unreadCount) {
        this.unreadCount = unreadCount;
    }
}