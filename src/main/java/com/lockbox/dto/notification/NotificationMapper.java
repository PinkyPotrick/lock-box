package com.lockbox.dto.notification;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.Notification;
import com.lockbox.model.User;
import com.lockbox.model.enums.NotificationStatus;

/**
 * Mapper class for converting between {@link Notification} entities and DTOs.
 */
@Component
public class NotificationMapper {

    /**
     * Convert a {@link Notification} entity to a {@link NotificationDTO}
     * 
     * @param notification - The Notification entity
     * @return {@link NotificationDTO} representation of the notification
     */
    public NotificationDTO toDTO(Notification notification) {
        if (notification == null) {
            return null;
        }

        NotificationDTO dto = new NotificationDTO();
        dto.setId(notification.getId());
        dto.setUserId(notification.getUser() != null ? notification.getUser().getId() : null);
        dto.setType(notification.getType());
        dto.setTitle(notification.getTitle());
        dto.setMessage(notification.getMessage());
        dto.setResourceId(notification.getResourceId());
        dto.setResourceType(notification.getResourceType());
        dto.setPriority(notification.getPriority());
        dto.setStatus(notification.getStatus());
        dto.setCreatedAt(notification.getCreatedAt());
        dto.setReadAt(notification.getReadAt());
        dto.setActionLink(notification.getActionLink());
        dto.setMetadata(notification.getMetadata());
        dto.setSentViaEmail(notification.getSentViaEmail());

        return dto;
    }

    /**
     * Convert a list of {@link Notification} entities to a list of {@link NotificationDTO}s
     * 
     * @param notifications - The list of Notification entities
     * @return List of {@link NotificationDTO}s
     */
    public List<NotificationDTO> toDTOList(List<Notification> notifications) {
        if (notifications == null) {
            return null;
        }

        return notifications.stream().map(this::toDTO).collect(Collectors.toList());
    }

    /**
     * Convert a {@link NotificationDTO} to a {@link Notification} entity
     * 
     * @param dto  - The NotificationDTO
     * @param user - The User entity associated with this notification
     * @return {@link Notification} entity
     */
    public Notification toEntity(NotificationDTO dto, User user) {
        if (dto == null) {
            return null;
        }

        Notification notification = new Notification();
        notification.setUser(user);
        notification.setType(dto.getType());
        notification.setTitle(dto.getTitle());
        notification.setMessage(dto.getMessage());
        notification.setResourceId(dto.getResourceId());
        notification.setResourceType(dto.getResourceType());
        notification.setPriority(dto.getPriority());
        notification.setStatus(dto.getStatus() != null ? dto.getStatus() : NotificationStatus.UNREAD);
        notification.setCreatedAt(dto.getCreatedAt() != null ? dto.getCreatedAt() : LocalDateTime.now());
        notification.setReadAt(dto.getReadAt());
        notification.setActionLink(dto.getActionLink());
        notification.setMetadata(dto.getMetadata());
        notification.setSentViaEmail(dto.getSentViaEmail() != null ? dto.getSentViaEmail() : false);

        return notification;
    }

    /**
     * Update a {@link Notification} entity from a {@link NotificationDTO}
     * 
     * @param entity - The existing Notification entity
     * @param dto    - The NotificationDTO with updated data
     * @return Updated {@link Notification} entity
     */
    public Notification updateEntityFromDTO(Notification entity, NotificationDTO dto) {
        if (entity == null || dto == null) {
            return entity;
        }

        if (dto.getTitle() != null) {
            entity.setTitle(dto.getTitle());
        }

        if (dto.getMessage() != null) {
            entity.setMessage(dto.getMessage());
        }

        if (dto.getStatus() != null) {
            entity.setStatus(dto.getStatus());
        }

        if (dto.getReadAt() != null) {
            entity.setReadAt(dto.getReadAt());
        }

        if (dto.getActionLink() != null) {
            entity.setActionLink(dto.getActionLink());
        }

        if (dto.getMetadata() != null) {
            entity.setMetadata(dto.getMetadata());
        }

        return entity;
    }
}