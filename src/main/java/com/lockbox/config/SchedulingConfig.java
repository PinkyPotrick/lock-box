package com.lockbox.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Configuration class to enable scheduled tasks in the application. This allows Spring to detect and run methods
 * annotated with @Scheduled.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
    // No additional beans or configuration needed
    // The @EnableScheduling annotation handles the setup
}