// package com.lockbox.config;

// import com.lockbox.security.filter.RateLimitingFilter;

// import jakarta.annotation.PostConstruct;

// import org.springframework.boot.web.servlet.FilterRegistrationBean;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;

// TODO : Do we need this?
// @Configuration
// public class SecurityConfig {

//     @PostConstruct
//     public void init() {
//         System.out.println("==== Security config initialized ====");
//     }

//     @Bean
//     public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilterRegistration(RateLimitingFilter filter) {
//         System.out.println("==== Registering rate limiting filter ====");
//         FilterRegistrationBean<RateLimitingFilter> registration = new FilterRegistrationBean<>();
//         registration.setFilter(filter);
//         registration.addUrlPatterns("/api/auth/*"); // Only apply to auth endpoints
//         registration.setOrder(1); // High priority
//         return registration;
//     }
// }