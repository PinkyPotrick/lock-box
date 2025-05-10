package com.lockbox.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.LoginHistory;

/**
 * Repository interface for {@link LoginHistory} entity. Provides methods to query and manage login history records in
 * the database.
 */
@Repository
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, String> {

    /**
     * Find login history entries by user ID ordered by login timestamp in descending order.
     * 
     * @param userId - The user ID to filter by
     * @return List of login history entries for the specified user
     */
    List<LoginHistory> findByUserIdOrderByLoginTimestampDesc(String userId);

    /**
     * Find a limited number of login history entries by user ID ordered by login timestamp in descending order.
     * 
     * @param userId - The user ID to filter by
     * @param limit  - The maximum number of entries to return
     * @return Limited list of login history entries for the specified user
     */
    @Query(value = "SELECT l FROM LoginHistory l WHERE l.userId = :userId ORDER BY l.loginTimestamp DESC")
    List<LoginHistory> findLatestByUserId(@Param("userId") String userId, @Param("limit") int limit);

    /**
     * Find login history entries by date and user ID.
     * 
     * @param date   - The date string in format "YYYY-MM-DD"
     * @param userId - The user ID to filter by
     * @return List of login history entries for the specified user and date
     */
    List<LoginHistory> findByDateAndUserIdOrderByLoginTimestampDesc(String date, String userId);

    /**
     * Find login history entries within a date range for a specific user.
     * 
     * @param startTime - The start date and time of the range
     * @param endTime   - The end date and time of the range
     * @param userId    - The user ID to filter by
     * @return List of login history entries within the specified date range for the user
     */
    List<LoginHistory> findByLoginTimestampBetweenAndUserIdOrderByLoginTimestampDesc(LocalDateTime startTime,
            LocalDateTime endTime, String userId);

    /**
     * Count the total number of login history entries for a specific user.
     * 
     * @param userId - The user ID to count entries for
     * @return Total count of login history entries for the user
     */
    int countByUserId(String userId);

    /**
     * Count the number of login history entries with a specific success status for a user.
     * 
     * @param userId  - The user ID to count entries for
     * @param success - The success status to filter by (true/false)
     * @return Count of login history entries matching the criteria
     */
    int countByUserIdAndSuccess(String userId, boolean success);
}