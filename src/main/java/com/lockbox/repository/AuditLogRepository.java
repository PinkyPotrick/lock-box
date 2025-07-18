package com.lockbox.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.AuditLog;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;

/**
 * Repository interface for {@link AuditLog} entities.
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    /**
     * Find all audit logs by user ID
     * 
     * @param userId - The user ID
     * @return List of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId ORDER BY a.timestamp DESC")
    List<AuditLog> findByUserId(@Param("userId") String userId);

    /**
     * Find all audit logs by user ID with pagination
     * 
     * @param userId   - The user ID
     * @param pageable - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserId(@Param("userId") String userId, Pageable pageable);

    /**
     * Find all audit logs by user ID and action type with pagination
     * 
     * @param userId     - The user ID
     * @param actionType - The action type
     * @param pageable   - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.actionType = :actionType ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndActionType(@Param("userId") String userId, @Param("actionType") String actionType,
            Pageable pageable);

    /**
     * Find all audit logs by user ID, operation type, and log level with pagination
     * 
     * @param userId        - The user ID
     * @param operationType - The operation type
     * @param logLevel      - The log level
     * @param pageable      - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.operationType = :operationType AND a.logLevel = :logLevel ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndOperationTypeAndLogLevel(@Param("userId") String userId,
            @Param("operationType") OperationType operationType, @Param("logLevel") LogLevel logLevel,
            Pageable pageable);

    /**
     * Find all audit logs by user ID and operation type with pagination
     * 
     * @param userId        - The user ID
     * @param operationType - The operation type
     * @param pageable      - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.operationType = :operationType ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndOperationType(@Param("userId") String userId,
            @Param("operationType") OperationType operationType, Pageable pageable);

    /**
     * Find all audit logs by user ID and log level with pagination
     * 
     * @param userId   - The user ID
     * @param logLevel - The log level
     * @param pageable - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.logLevel = :logLevel ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndLogLevel(@Param("userId") String userId, @Param("logLevel") LogLevel logLevel,
            Pageable pageable);

    /**
     * Find all audit logs by user ID and date range with pagination
     * 
     * @param userId    - The user ID
     * @param startDate - Start date of range
     * @param endDate   - End date of range
     * @param pageable  - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndTimestampBetween(@Param("userId") String userId,
            @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

    /**
     * Find all audit logs by user ID, operation type, log level and date range with pagination
     * 
     * @param userId        - The user ID
     * @param operationType - The operation type
     * @param logLevel      - The log level
     * @param startDate     - Start date of range
     * @param endDate       - End date of range
     * @param pageable      - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.operationType = :operationType AND a.logLevel = :logLevel AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndOperationTypeAndLogLevelAndTimestampBetween(@Param("userId") String userId,
            @Param("operationType") OperationType operationType, @Param("logLevel") LogLevel logLevel,
            @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

    /**
     * Find all audit logs by user ID, operation type and date range with pagination
     * 
     * @param userId        - The user ID
     * @param operationType - The operation type
     * @param startDate     - Start date of range
     * @param endDate       - End date of range
     * @param pageable      - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.operationType = :operationType AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndOperationTypeAndTimestampBetween(@Param("userId") String userId,
            @Param("operationType") OperationType operationType, @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate, Pageable pageable);

    /**
     * Find all audit logs by user ID, log level and date range with pagination
     * 
     * @param userId    - The user ID
     * @param logLevel  - The log level
     * @param startDate - Start date of range
     * @param endDate   - End date of range
     * @param pageable  - Pagination information
     * @return Page of audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.logLevel = :logLevel AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserIdAndLogLevelAndTimestampBetween(@Param("userId") String userId,
            @Param("logLevel") LogLevel logLevel, @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate, Pageable pageable);

    /**
     * Count audit logs by user ID
     * 
     * @param userId - The user ID
     * @return Count of audit logs
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.user.id = :userId")
    int countByUserId(@Param("userId") String userId);

    /**
     * Delete audit logs older than the specified date
     * 
     * @param cutoffDate - Date threshold for deletion
     * @return Number of records deleted
     */
    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoffDate")
    int deleteByTimestampBefore(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Count audit logs by user ID and action types after a specific timestamp
     * 
     * @param userId      - The user ID
     * @param actionTypes - List of action types to count
     * @param timestamp   - Count only logs after this timestamp
     * @return Count of matching audit logs
     */
    int countByUserIdAndActionTypeInAndTimestampAfter(String userId, List<ActionType> actionTypes,
            LocalDateTime timestamp);

    /**
     * Find recent login-related audit logs for a user
     * 
     * @param userId      - The user ID
     * @param actionTypes - List of action types to find
     * @param limit       - Maximum number of logs to return
     * @return List of matching audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.actionType IN :actionTypes ORDER BY a.timestamp DESC")
    List<AuditLog> findRecentLoginLogs(@Param("userId") String userId,
            @Param("actionTypes") List<ActionType> actionTypes, Pageable pageable);
}