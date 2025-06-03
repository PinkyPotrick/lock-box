package com.lockbox.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.AuditLog;

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
    Page<AuditLog> findByUserIdAndActionType(@Param("userId") String userId,
            @Param("actionType") String actionType,
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
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            Pageable pageable);

    /**
     * Count audit logs by user ID
     * 
     * @param userId - The user ID
     * @return Count of audit logs
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.user.id = :userId")
    int countByUserId(@Param("userId") String userId);
}