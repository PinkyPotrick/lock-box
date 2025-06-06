package com.lockbox.dto.notification;

import java.time.LocalDateTime;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;
import com.lockbox.model.NotificationPriority;
import com.lockbox.model.NotificationStatus;
import com.lockbox.model.NotificationType;
import com.lockbox.model.ResourceType;

public class NotificationResponseDTO {

    private String id;
    private String userId;
    private NotificationType type;
    private EncryptedDataAesCbcDTO encryptedTitle;
    private EncryptedDataAesCbcDTO encryptedMessage;
    private EncryptedDataAesCbcDTO encryptedResourceId;
    private ResourceType resourceType;
    private NotificationPriority priority;
    private NotificationStatus status;
    private LocalDateTime createdAt;
    private LocalDateTime readAt;
    private EncryptedDataAesCbcDTO encryptedActionLink;
    private EncryptedDataAesCbcDTO encryptedMetadata;
    private Boolean sentViaEmail;
    private String helperAesKey;

    public NotificationResponseDTO() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public NotificationType getType() {
        return type;
    }

    public void setType(NotificationType type) {
        this.type = type;
    }

    public EncryptedDataAesCbcDTO getEncryptedTitle() {
        return encryptedTitle;
    }

    public void setEncryptedTitle(EncryptedDataAesCbcDTO encryptedTitle) {
        this.encryptedTitle = encryptedTitle;
    }

    public EncryptedDataAesCbcDTO getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(EncryptedDataAesCbcDTO encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public EncryptedDataAesCbcDTO getEncryptedResourceId() {
        return encryptedResourceId;
    }

    public void setEncryptedResourceId(EncryptedDataAesCbcDTO encryptedResourceId) {
        this.encryptedResourceId = encryptedResourceId;
    }

    public ResourceType getResourceType() {
        return resourceType;
    }

    public void setResourceType(ResourceType resourceType) {
        this.resourceType = resourceType;
    }

    public NotificationPriority getPriority() {
        return priority;
    }

    public void setPriority(NotificationPriority priority) {
        this.priority = priority;
    }

    public NotificationStatus getStatus() {
        return status;
    }

    public void setStatus(NotificationStatus status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getReadAt() {
        return readAt;
    }

    public void setReadAt(LocalDateTime readAt) {
        this.readAt = readAt;
    }

    public EncryptedDataAesCbcDTO getEncryptedActionLink() {
        return encryptedActionLink;
    }

    public void setEncryptedActionLink(EncryptedDataAesCbcDTO encryptedActionLink) {
        this.encryptedActionLink = encryptedActionLink;
    }

    public EncryptedDataAesCbcDTO getEncryptedMetadata() {
        return encryptedMetadata;
    }

    public void setEncryptedMetadata(EncryptedDataAesCbcDTO encryptedMetadata) {
        this.encryptedMetadata = encryptedMetadata;
    }

    public Boolean getSentViaEmail() {
        return sentViaEmail;
    }

    public void setSentViaEmail(Boolean sentViaEmail) {
        this.sentViaEmail = sentViaEmail;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}