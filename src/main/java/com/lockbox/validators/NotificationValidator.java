package com.lockbox.validators;

import java.util.List;

import org.springframework.stereotype.Component;

import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationMarkReadRequestDTO;
import com.lockbox.dto.notification.NotificationRequestDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;
import com.lockbox.utils.AppConstants.ValidationErrors;

/**
 * Validator for notification-related DTOs.
 */
@Component
public class NotificationValidator extends BaseValidator {

    /**
     * Creates a new notification validator.
     */
    public NotificationValidator() {
        super(AppConstants.EntityTypes.NOTIFICATION);
    }

    /**
     * Validate a notification DTO
     * 
     * @param notificationDTO - The notification DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateNotificationDTO(NotificationDTO notificationDTO) throws ValidationException {
        validateNotNull(notificationDTO, FieldNames.NOTIFICATION_DATA);
        validateNotNull(notificationDTO.getType(), FieldNames.NOTIFICATION_TYPE,
                ValidationErrors.NOTIFICATION_TYPE_REQUIRED);
        validateRequired(notificationDTO.getTitle(), FieldNames.TITLE, ValidationErrors.TITLE_REQUIRED);
        validateRequired(notificationDTO.getMessage(), FieldNames.MESSAGE, ValidationErrors.MESSAGE_REQUIRED);
        validateNotNull(notificationDTO.getPriority(), FieldNames.PRIORITY, ValidationErrors.PRIORITY_REQUIRED);

        if (hasContent(notificationDTO.getTitle())) {
            validateMaxLength(notificationDTO.getTitle(), MaxLengths.TITLE, FieldNames.TITLE);
            validateSecure(notificationDTO.getTitle(), FieldNames.TITLE);
        }

        if (hasContent(notificationDTO.getMessage())) {
            validateMaxLength(notificationDTO.getMessage(), MaxLengths.MESSAGE, FieldNames.MESSAGE);
            validateSecure(notificationDTO.getMessage(), FieldNames.MESSAGE);
        }

        if (hasContent(notificationDTO.getResourceId())) {
            validateMaxLength(notificationDTO.getResourceId(), MaxLengths.RESOURCE_ID, FieldNames.RESOURCE_ID);
            validateSecure(notificationDTO.getResourceId(), FieldNames.RESOURCE_ID);
        }

        if (hasContent(notificationDTO.getActionLink())) {
            validateMaxLength(notificationDTO.getActionLink(), MaxLengths.ACTION_LINK, FieldNames.ACTION_LINK);
            validateSecure(notificationDTO.getActionLink(), FieldNames.ACTION_LINK);
        }

        if (hasContent(notificationDTO.getMetadata())) {
            validateMaxLength(notificationDTO.getMetadata(), MaxLengths.METADATA, FieldNames.METADATA);
            validateSecure(notificationDTO.getMetadata(), FieldNames.METADATA);
        }
    }

    /**
     * Validate a notification request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateNotificationRequest(NotificationRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.NOTIFICATION_REQUEST);
        validateNotNull(requestDTO.getType(), FieldNames.NOTIFICATION_TYPE,
                ValidationErrors.NOTIFICATION_TYPE_REQUIRED);
        validateNotNull(requestDTO.getEncryptedTitle(), FieldNames.TITLE, ValidationErrors.TITLE_REQUIRED);
        validateNotNull(requestDTO.getEncryptedMessage(), FieldNames.MESSAGE, ValidationErrors.MESSAGE_REQUIRED);
        validateNotNull(requestDTO.getPriority(), FieldNames.PRIORITY, ValidationErrors.PRIORITY_REQUIRED);
        validateNotNull(requestDTO.getHelperAesKey(), FieldNames.ENCRYPTION_KEY,
                ValidationErrors.ENCRYPTION_KEY_REQUIRED);
    }

    /**
     * Validate a mark read request DTO
     * 
     * @param requestDTO - The mark read request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateMarkReadRequest(NotificationMarkReadRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, "Mark read request");

        List<String> notificationIds = requestDTO.getNotificationIds();
        validateNotNull(notificationIds, "Notification IDs");

        if (notificationIds.isEmpty()) {
            throwValidationException("At least one notification ID must be provided");
        }

        // Check that each ID is valid
        for (String id : notificationIds) {
            validateRequired(id, "Notification ID", "Invalid notification ID");
        }
    }
}