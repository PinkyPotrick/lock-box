package com.lockbox.service.auditlog;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogMapper;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.model.ActionType;
import com.lockbox.model.AuditLog;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
import com.lockbox.model.User;
import com.lockbox.repository.AuditLogRepository;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.Errors;
import com.lockbox.utils.RequestUtils;
import com.lockbox.validators.AuditLogValidator;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Implementation of the {@link AuditLogService} interface. Provides functionality for managing {@link AuditLog}
 * entities.
 */
@Service
public class AuditLogServiceImpl implements AuditLogService {

    private final Logger logger = LoggerFactory.getLogger(AuditLogServiceImpl.class);

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogServerEncryptionService auditLogServerEncryptionService;

    @Autowired
    private AuditLogClientEncryptionService auditLogClientEncryptionService;

    @Autowired
    private AuditLogValidator auditLogValidator;

    @Autowired
    private AuditLogMapper auditLogMapper;

    /**
     * Find all audit logs for the current user with optional pagination.
     * 
     * @param userId - The current user ID
     * @param page   - Optional page number (0-based index), can be null
     * @param size   - Optional page size, can be null
     * @return {@link AuditLogListResponseDTO} containing encrypted audit logs
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public AuditLogListResponseDTO findAllAuditLogsByUser(String userId, Integer page, Integer size) throws Exception {
        try {
            List<AuditLog> encryptedAuditLogs;

            // Create pageable object inside the service if pagination parameters are
            // provided
            if (page != null && size != null) {
                Pageable pageable = PageRequest.of(page, size);
                Page<AuditLog> auditLogPage = auditLogRepository.findByUserId(userId, pageable);
                encryptedAuditLogs = auditLogPage.getContent();
            } else {
                encryptedAuditLogs = auditLogRepository.findByUserId(userId);
            }

            List<AuditLog> decryptedAuditLogs = new ArrayList<>();

            // Decrypt each audit log retrieved from database
            for (AuditLog encryptedAuditLog : encryptedAuditLogs) {
                decryptedAuditLogs.add(auditLogServerEncryptionService.decryptServerData(encryptedAuditLog));
            }

            // Convert to DTOs
            List<AuditLogDTO> auditLogDTOs = auditLogMapper.toDTOList(decryptedAuditLogs);

            // Encrypt for client response
            return auditLogClientEncryptionService.encryptAuditLogListForClient(auditLogDTOs);
        } catch (Exception e) {
            logger.error("Error fetching audit logs for user {}: {}", userId, e.getMessage());
            throw new Exception(Errors.FETCH_AUDIT_LOGS_FAILED, e);
        }
    }

    /**
     * Find audit logs for the current user by action type with optional pagination.
     * 
     * @param userId     - The current user ID
     * @param actionType - The action type to filter by
     * @param page       - Optional page number (0-based index), can be null
     * @param size       - Optional page size, can be null
     * @return {@link AuditLogListResponseDTO} containing encrypted audit logs
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public AuditLogListResponseDTO findAuditLogsByUserAndType(String userId, String actionType, Integer page,
            Integer size) throws Exception {
        try {
            List<AuditLog> encryptedAuditLogs;

            // Create pageable object
            Pageable pageable = (page != null && size != null) ? PageRequest.of(page, size) : PageRequest.of(0, 100);
            Page<AuditLog> auditLogPage = auditLogRepository.findByUserIdAndActionType(userId, actionType, pageable);
            encryptedAuditLogs = auditLogPage.getContent();

            List<AuditLog> decryptedAuditLogs = new ArrayList<>();

            // Decrypt each audit log retrieved from database
            for (AuditLog encryptedAuditLog : encryptedAuditLogs) {
                decryptedAuditLogs.add(auditLogServerEncryptionService.decryptServerData(encryptedAuditLog));
            }

            // Convert to DTOs
            List<AuditLogDTO> auditLogDTOs = auditLogMapper.toDTOList(decryptedAuditLogs);

            // Encrypt for client response
            return auditLogClientEncryptionService.encryptAuditLogListForClient(auditLogDTOs);
        } catch (Exception e) {
            logger.error("Error fetching audit logs for user {} and action type {}: {}", userId, actionType,
                    e.getMessage());
            throw new Exception(Errors.FETCH_AUDIT_LOGS_FAILED, e);
        }
    }

    /**
     * Find audit logs for the current user with multiple filters and pagination.
     * 
     * @param userId        - The current user ID
     * @param operationType - Operation type filter (can be null for no filter)
     * @param logLevel      - Log level filter (can be null for no filter)
     * @param startDate     - Start of date range (can be null for no lower bound)
     * @param endDate       - End of date range (can be null for no upper bound)
     * @param page          - Page number (0-based index)
     * @param size          - Page size
     * @return {@link AuditLogListResponseDTO} containing encrypted audit logs
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public AuditLogListResponseDTO findAuditLogsByUserAndFilters(String userId, OperationType operationType,
            LogLevel logLevel, LocalDateTime startDate, LocalDateTime endDate, Integer page, Integer size)
            throws Exception {
        try {
            Pageable pageable = (page != null && size != null) ? PageRequest.of(page, size) : PageRequest.of(0, 100);
            Page<AuditLog> auditLogPage;

            // Handle all the filter combinations
            if (operationType != null && logLevel != null && startDate != null && endDate != null) {
                // All filters applied
                auditLogPage = auditLogRepository.findByUserIdAndOperationTypeAndLogLevelAndTimestampBetween(userId,
                        operationType, logLevel, startDate, endDate, pageable);
            } else if (operationType != null && logLevel != null) {
                // Operation type and log level filters only
                auditLogPage = auditLogRepository.findByUserIdAndOperationTypeAndLogLevel(userId, operationType,
                        logLevel, pageable);
            } else if (operationType != null && startDate != null && endDate != null) {
                // Operation type and date range filters only
                auditLogPage = auditLogRepository.findByUserIdAndOperationTypeAndTimestampBetween(userId, operationType,
                        startDate, endDate, pageable);
            } else if (logLevel != null && startDate != null && endDate != null) {
                // Log level and date range filters only
                auditLogPage = auditLogRepository.findByUserIdAndLogLevelAndTimestampBetween(userId, logLevel,
                        startDate, endDate, pageable);
            } else if (operationType != null) {
                // Operation type filter only
                auditLogPage = auditLogRepository.findByUserIdAndOperationType(userId, operationType, pageable);
            } else if (logLevel != null) {
                // Log level filter only
                auditLogPage = auditLogRepository.findByUserIdAndLogLevel(userId, logLevel, pageable);
            } else if (startDate != null && endDate != null) {
                // Date range filter only
                auditLogPage = auditLogRepository.findByUserIdAndTimestampBetween(userId, startDate, endDate, pageable);
            } else {
                // No filters, return all logs
                auditLogPage = auditLogRepository.findByUserId(userId, pageable);
            }

            List<AuditLog> encryptedAuditLogs = auditLogPage.getContent();
            List<AuditLog> decryptedAuditLogs = new ArrayList<>();

            // Decrypt each audit log retrieved from database
            for (AuditLog encryptedAuditLog : encryptedAuditLogs) {
                decryptedAuditLogs.add(auditLogServerEncryptionService.decryptServerData(encryptedAuditLog));
            }

            // Convert to DTOs
            List<AuditLogDTO> auditLogDTOs = auditLogMapper.toDTOList(decryptedAuditLogs);

            // Encrypt for client response
            return auditLogClientEncryptionService.encryptAuditLogListForClient(auditLogDTOs);
        } catch (Exception e) {
            logger.error("Error fetching filtered audit logs for user {}: {}", userId, e.getMessage());
            throw new Exception(Errors.FETCH_AUDIT_LOGS_FAILED, e);
        }
    }

    /**
     * Find audit logs for the current user by date range with optional pagination.
     * 
     * @param userId    - The current user ID
     * @param startDate - The start date of the range
     * @param endDate   - The end date of the range
     * @param page      - Optional page number (0-based index), can be null
     * @param size      - Optional page size, can be null
     * @return {@link AuditLogListResponseDTO} containing encrypted audit logs
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public AuditLogListResponseDTO findAuditLogsByUserAndDateRange(String userId, LocalDateTime startDate,
            LocalDateTime endDate, Integer page, Integer size) throws Exception {
        try {
            List<AuditLog> encryptedAuditLogs;            // Create pageable object
            Pageable pageable = (page != null && size != null) ? 
                    PageRequest.of(page, size) : 
                    PageRequest.of(AppConstants.DEFAULT_PAGE_NUMBER, AppConstants.DEFAULT_PAGE_SIZE);
            Page<AuditLog> auditLogPage = auditLogRepository.findByUserIdAndTimestampBetween(userId, startDate, endDate,
                    pageable);
            encryptedAuditLogs = auditLogPage.getContent();

            List<AuditLog> decryptedAuditLogs = new ArrayList<>();

            // Decrypt each audit log retrieved from database
            for (AuditLog encryptedAuditLog : encryptedAuditLogs) {
                decryptedAuditLogs.add(auditLogServerEncryptionService.decryptServerData(encryptedAuditLog));
            }

            // Convert to DTOs
            List<AuditLogDTO> auditLogDTOs = auditLogMapper.toDTOList(decryptedAuditLogs);

            // Encrypt for client response
            return auditLogClientEncryptionService.encryptAuditLogListForClient(auditLogDTOs);        } catch (Exception e) {
            logger.error("Error fetching audit logs for user {} in date range: {}", userId, e.getMessage());
            throw new Exception(AppConstants.Errors.FETCH_AUDIT_LOGS_FAILED, e);
        }
    }

    /**
     * Create a new audit log entry.
     * 
     * @param auditLogDTO - The audit log data to save
     * @param userId      - The current user ID
     * @return Created {@link AuditLogResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public AuditLogResponseDTO createAuditLog(AuditLogDTO auditLogDTO, String userId) throws Exception {
        try {
            // Validate the audit log data
            auditLogValidator.validateAuditLogDTO(auditLogDTO);            // Find the user
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                throw new RuntimeException(AppConstants.Errors.USER_NOT_FOUND);
            }

            // Create the audit log entity
            AuditLog auditLog = auditLogMapper.toEntity(auditLogDTO, userOpt.get());

            // Set timestamp if not provided
            if (auditLog.getTimestamp() == null) {
                auditLog.setTimestamp(LocalDateTime.now());
            }

            // Encrypt and save
            AuditLog encryptedAuditLog = auditLogServerEncryptionService.encryptServerData(auditLog);
            AuditLog savedAuditLog = auditLogRepository.save(encryptedAuditLog);

            // Decrypt for response
            AuditLog decryptedAuditLog = auditLogServerEncryptionService.decryptServerData(savedAuditLog);

            // Convert to DTO
            AuditLogDTO responseDTO = auditLogMapper.toDTO(decryptedAuditLog);

            // Encrypt for client response
            return auditLogClientEncryptionService.encryptAuditLogForClient(responseDTO);        } catch (Exception e) {
            logger.error("Error creating audit log: {}", e.getMessage());
            throw new Exception(AppConstants.Errors.CREATE_AUDIT_LOG_FAILED, e);
        }
    }

    /**
     * Helper method to quickly create audit logs from other services
     * 
     * @param userId         - User ID performing the action
     * @param actionType     - Type of action (e.g., "CREDENTIAL_VIEW", "PASSWORD_UPDATE")
     * @param operationType  - Operation category (READ, WRITE, UPDATE, DELETE)
     * @param logLevel       - Severity level of the log
     * @param resourceId     - ID of the resource being accessed (can be null)
     * @param resourceName   - Name of the resource being accessed (can be null)
     * @param status         - Outcome status ("SUCCESS" or "FAILURE")
     * @param failureReason  - Reason for failure (null if successful)
     * @param additionalInfo - Any additional context information
     * @return The created AuditLog response
     */
    @Override
    public AuditLogResponseDTO logUserAction(String userId, ActionType actionType, OperationType operationType,
            LogLevel logLevel, String resourceId, String resourceName, String status, String failureReason,
            String additionalInfo) throws Exception {

        AuditLogDTO logDTO = new AuditLogDTO();
        logDTO.setActionType(actionType);
        logDTO.setOperationType(operationType);
        logDTO.setLogLevel(logLevel);
        logDTO.setResourceId(resourceId);
        logDTO.setResourceName(resourceName);
        logDTO.setActionStatus(status);
        logDTO.setFailureReason(failureReason);
        logDTO.setAdditionalInfo(additionalInfo);

        // Get the current request from RequestContextHolder
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                .getRequest();
        logDTO.setIpAddress(RequestUtils.getClientIpAddress(request));
        logDTO.setClientInfo(request.getHeader("User-Agent"));
        logDTO.setFailureReason(failureReason);
        logDTO.setAdditionalInfo(additionalInfo);
        logDTO.setIpAddress(RequestUtils.getClientIpAddress(request));
        logDTO.setClientInfo(request.getHeader("User-Agent"));

        return this.createAuditLog(logDTO, userId);
    }

    /**
     * Delete audit logs older than the specified cutoff date. Default retention period is 3 months.
     * 
     * @param cutoffDate - Delete logs older than this date
     * @return Number of logs deleted
     * @throws Exception If deletion fails
     */    @Override
    @Transactional
    public int deleteOldAuditLogs(LocalDateTime cutoffDate) throws Exception {
        try {
            logger.info("Deleting audit logs older than {}", cutoffDate);
            int deletedCount = auditLogRepository.deleteByTimestampBefore(cutoffDate);
            logger.info(AppConstants.SchedulerMessages.CLEANUP_COMPLETE, deletedCount);
            return deletedCount;
        } catch (Exception e) {
            logger.error(AppConstants.SchedulerMessages.CLEANUP_ERROR, e.getMessage());
            throw new Exception("Failed to delete old audit logs", e);
        }
    }/**
     * Delete audit logs older than the default retention period (3 months).
     * 
     * @return Number of logs deleted
     * @throws Exception If deletion fails
     */
    @Override
    @Transactional
    public int deleteOldAuditLogs() throws Exception {
        // Use the default retention period from constants
        LocalDateTime cutoffDate = LocalDateTime.now().minus(
            AppConstants.DEFAULT_AUDIT_LOG_RETENTION_MONTHS, 
            AppConstants.AUDIT_LOG_RETENTION_UNIT);
        return deleteOldAuditLogs(cutoffDate);
    }

    /**
     * Get filtered audit logs based on the provided parameters. This method handles all the parameter parsing and
     * validation logic.
     *
     * @param userId        User ID to filter logs for
     * @param page          Page number (0-based)
     * @param size          Page size
     * @param operationType Operation type filter string
     * @param level         Log level filter string
     * @param startDateStr  Start date as ISO string
     * @param endDateStr    End date as ISO string
     * @return Filtered and paginated audit logs
     * @throws Exception If filtering fails
     */
    @Override
    public AuditLogListResponseDTO getFilteredAuditLogs(String userId, Integer page, Integer size, String operationType,
            String level, String startDateStr, String endDateStr) throws Exception {

        try {
            // Validate the filter parameters
            auditLogValidator.validateFilterParameters(operationType, level, startDateStr, endDateStr);

            // Parse date parameters if present
            LocalDateTime startDate = null;
            LocalDateTime endDate = null;

            if (startDateStr != null && !startDateStr.isEmpty()) {
                startDate = LocalDateTime.parse(startDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            }

            if (endDateStr != null && !endDateStr.isEmpty()) {
                endDate = LocalDateTime.parse(endDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            }

            // Parse operation type if present
            OperationType opType = null;
            if (operationType != null && !operationType.isEmpty() && !operationType.equalsIgnoreCase("ALL")) {
                opType = OperationType.valueOf(operationType.toUpperCase());
            }

            // Parse log level if present
            LogLevel logLevel = null;
            if (level != null && !level.isEmpty() && !level.equalsIgnoreCase("ALL")) {
                logLevel = LogLevel.valueOf(level.toUpperCase());
            }

            // Find logs with filters
            return findAuditLogsByUserAndFilters(userId, opType, logLevel, startDate, endDate, page, size);
        } catch (ValidationException e) {
            throw e; // Let the controller handle the validation exception
        } catch (Exception e) {
            logger.error("Error fetching filtered audit logs: {}", e.getMessage(), e);
            throw new Exception(Errors.FETCH_AUDIT_LOGS_FAILED, e);
        }
    }
}