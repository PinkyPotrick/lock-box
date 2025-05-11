package com.lockbox.model;

public enum CredentialCategory {
    SOCIAL_MEDIA("Social Media"), //
    BANKING("Banking"), //
    EMAIL("Email"), //
    SHOPPING("Shopping"), //
    WORK("Work"), //
    ENTERTAINMENT("Entertainment"), //
    DEVELOPMENT("Development"), //
    PERSONAL("Personal"), //
    EDUCATION("Education"), //
    FINANCE("Finance"), //
    TRAVEL("Travel"), //
    HEALTH("Health"), //
    GAMING("Gaming"), //
    COMMUNICATION("Communication"), //
    PRODUCTIVITY("Productivity"), //
    CLOUD_STORAGE("Cloud Storage"), //
    SECURITY("Security"), //
    OTHER("Other"); //

    private final String displayName;

    CredentialCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static boolean isValid(String category) {
        if (category == null || category.isEmpty()) {
            return true;
        }

        for (CredentialCategory validCategory : CredentialCategory.values()) {
            if (validCategory.getDisplayName().equalsIgnoreCase(category)) {
                return true;
            }
        }

        return false;
    }

    public static CredentialCategory fromString(String category) {
        if (category == null) {
            return null;
        }

        for (CredentialCategory validCategory : CredentialCategory.values()) {
            if (validCategory.getDisplayName().equalsIgnoreCase(category)) {
                return validCategory;
            }
        }

        return null;
    }

    public static String[] getAllDisplayNames() {
        CredentialCategory[] categories = CredentialCategory.values();
        String[] displayNames = new String[categories.length];

        for (int i = 0; i < categories.length; i++) {
            displayNames[i] = categories[i].getDisplayName();
        }

        return displayNames;
    }
}