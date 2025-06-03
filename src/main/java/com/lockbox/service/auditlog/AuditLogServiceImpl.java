package com.lockbox.service.auditlog;

import java.time.LocalDateTime;
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

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogMapper;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;
import com.lockbox.model.AuditLog;
import com.lockbox.model.User;
import com.lockbox.repository.AuditLogRepository;
import com.lockbox.repository.UserRepository;
import com.lockbox.validators.AuditLogValidator;

/**
 * Implementation of the {@link AuditLogService} interface. Provides
 * functionality for managing {@link AuditLog} entities.
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
            int totalCount;

            // Create pageable object inside the service if pagination parameters are
            // provided
            if (page != null && size != null) {
                Pageable pageable = PageRequest.of(page, size);
                Page<AuditLog> auditLogPage = auditLogRepository.findByUserId(userId, pageable);
                encryptedAuditLogs = auditLogPage.getContent();
                totalCount = (int) auditLogPage.getTotalElements();
            } else {
                encryptedAuditLogs = auditLogRepository.findByUserId(userId);
                totalCount = encryptedAuditLogs.size();
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
            throw new Exception("Failed to fetch audit logs", e);
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
            Integer size)
            throws Exception {
        try {
            List<AuditLog> encryptedAuditLogs;
            int totalCount;

            // Create pageable object
            Pageable pageable = (page != null && size != null) ? PageRequest.of(page, size) : PageRequest.of(0, 100);
            Page<AuditLog> auditLogPage = auditLogRepository.findByUserIdAndActionType(userId, actionType, pageable);
            encryptedAuditLogs = auditLogPage.getContent();
            totalCount = (int) auditLogPage.getTotalElements();

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
            throw new Exception("Failed to fetch audit logs", e);
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
            LocalDateTime endDate, Integer page, Integer size)
            throws Exception {
        try {
            List<AuditLog> encryptedAuditLogs;
            int totalCount;

            // Create pageable object
            Pageable pageable = (page != null && size != null) ? PageRequest.of(page, size) : PageRequest.of(0, 100);
            Page<AuditLog> auditLogPage = auditLogRepository.findByUserIdAndTimestampBetween(
                    userId, startDate, endDate, pageable);
            encryptedAuditLogs = auditLogPage.getContent();
            totalCount = (int) auditLogPage.getTotalElements();

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
            logger.error("Error fetching audit logs for user {} in date range: {}", userId, e.getMessage());
            throw new Exception("Failed to fetch audit logs", e);
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
            auditLogValidator.validateAuditLogDTO(auditLogDTO);

            // Find the user
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                throw new RuntimeException("User not found");
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
            return auditLogClientEncryptionService.encryptAuditLogForClient(responseDTO);
        } catch (Exception e) {
            logger.error("Error creating audit log: {}", e.getMessage());
            throw new Exception("Failed to create audit log", e);
        }
    }

    /**
     * Delete audit logs older than the specified cutoff date.
     * 
     * @param cutoffDate - Delete logs older than this date
     * @throws Exception If deletion fails
     */
    @Override
    @Transactional
    public void deleteOldAuditLogs(LocalDateTime cutoffDate) throws Exception {
        try {
            // This would require a custom repository method for efficient deletion
            // For now, we'll get the logs and delete them one by one

            // This approach is not recommended for production with large volumes
            // Consider implementing a native query for batch deletion

            logger.info("Deleting audit logs older than {}", cutoffDate);

            // TODO: Implement when needed, using a more efficient approach
            // auditLogRepository.deleteByTimestampBefore(cutoffDate);

        } catch (Exception e) {
            logger.error("Error deleting old audit logs: {}", e.getMessage());
            throw new Exception("Failed to delete old audit logs", e);
        }
    }
}