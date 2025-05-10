package com.lockbox.dto.loginhistory;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.LoginHistory;
import com.lockbox.utils.UserAgentParser;

/**
 * Mapper for converting between {@link LoginHistory} entities and DTOs.
 */
@Component
public class LoginHistoryMapper {

    /**
     * Converts a {@link LoginHistory} entity to a {@link LoginHistoryDTO} with additional parsed information.
     * 
     * @param loginHistory - The {@link LoginHistory} entity to convert
     * @return {@link LoginHistoryDTO} with entity data and parsed user agent information
     */
    public LoginHistoryDTO toDTO(LoginHistory loginHistory) {
        if (loginHistory == null) {
            return null;
        }

        LoginHistoryDTO dto = new LoginHistoryDTO();

        // Map basic fields
        dto.setId(loginHistory.getId());
        dto.setUserId(loginHistory.getUserId());
        dto.setLoginTimestamp(loginHistory.getLoginTimestamp());
        dto.setDate(loginHistory.getDate());
        dto.setIpAddress(loginHistory.getIpAddress());
        dto.setUserAgent(loginHistory.getUserAgent());
        dto.setSuccess(loginHistory.isSuccess());
        dto.setFailureReason(loginHistory.getFailureReason());

        // Parse user agent for additional info if available
        if (loginHistory.getUserAgent() != null) {
            UserAgentParser.UserAgentInfo userAgentInfo = UserAgentParser.parse(loginHistory.getUserAgent());
            dto.setBrowser(userAgentInfo.getBrowser());
            dto.setDeviceType(userAgentInfo.getDeviceType());
        }

        return dto;
    }

    /**
     * Converts a list of {@link LoginHistory} entities to a list of {@link LoginHistoryDTO}.
     * 
     * @param loginHistories - The list of {@link LoginHistory} entities to convert
     * @return List of {@link LoginHistoryDTO}
     */
    public List<LoginHistoryDTO> toDTOList(List<LoginHistory> loginHistories) {
        if (loginHistories == null) {
            return null;
        }

        return loginHistories.stream().map(this::toDTO).collect(Collectors.toList());
    }

    /**
     * Creates a {@link LoginHistoryListDTO} from a list of {@link LoginHistoryDTO} and count data.
     * 
     * @param dtos         - The list of LoginHistoryDTOs
     * @param totalCount   - The total count of login history entries
     * @param successCount - The count of successful login attempts
     * @param failureCount - The count of failed login attempts
     * @return {@link LoginHistoryListDTO} containing the list and statistics
     */
    public LoginHistoryListDTO toListDTO(List<LoginHistoryDTO> dtos, long totalCount, int successCount,
            int failureCount) {
        return new LoginHistoryListDTO(dtos, totalCount, successCount, failureCount);
    }
}