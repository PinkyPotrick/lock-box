package com.lockbox.utils;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AdminUtils {

    @Value("${admin.usernames:}")
    private String adminUsernames;

    @Value("${admin.ids:}")
    private String adminUserIds;

    private List<String> adminUsernameList;
    private List<String> adminUserIdList;

    public boolean isAdmin(String username) {
        if (adminUsernameList == null && !adminUsernames.isEmpty()) {
            adminUsernameList = Arrays.asList(adminUsernames.split(","));
        }
        return adminUsernameList != null && adminUsernameList.contains(username);
    }

    public boolean isAdminById(String userId) {
        if (adminUserIdList == null && !adminUserIds.isEmpty()) {
            adminUserIdList = Arrays.asList(adminUserIds.split(","));
        }
        return adminUserIdList != null && adminUserIdList.contains(userId);
    }
}