package com.lockbox.dto.notification;

import java.util.List;

public class NotificationListResponseDTO {

    private List<NotificationResponseDTO> notifications;
    private int totalCount;

    public NotificationListResponseDTO() {
    }

    public NotificationListResponseDTO(List<NotificationResponseDTO> notifications, int totalCount) {
        this.notifications = notifications;
        this.totalCount = totalCount;
    }

    public List<NotificationResponseDTO> getNotifications() {
        return notifications;
    }

    public void setNotifications(List<NotificationResponseDTO> notifications) {
        this.notifications = notifications;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }
}