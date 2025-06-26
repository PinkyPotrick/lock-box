package com.lockbox.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.VersionResourceResolver;

import com.lockbox.security.filter.CustomIpFilter;
import com.lockbox.security.filter.JwtAuthenticationFilter;
import com.lockbox.security.filter.RateLimitingFilter;
import com.lockbox.security.interceptor.TotpRequiredInterceptor;

/**
 * Spring MVC configuration for CORS settings, static resources, and other web-related concerns.
 * 
 * Security notes: 1. Static resources are restricted to /static/** paths only 2. CORS is configured to allow only
 * specific trusted origins 3. In production, update allowed origins to actual domain names
 */
@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private CustomIpFilter customIpFilter;

    @Autowired
    private RateLimitingFilter rateLimitingFilter;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private TotpRequiredInterceptor totpRequiredInterceptor;

    @Bean
    public FilterRegistrationBean<CustomIpFilter> customIpFilterRegistration() {
        FilterRegistrationBean<CustomIpFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(customIpFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilterRegistration() {
        FilterRegistrationBean<RateLimitingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(rateLimitingFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(2);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration() {
        FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(jwtAuthenticationFilter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(3);
        return registration;
    }

    @Override
    public void addResourceHandlers(@NonNull ResourceHandlerRegistry registry) {
        // Only serve static resources from /static/** path to prevent exposing API endpoints
        // as static resources, which could lead to security issues
        registry.addResourceHandler("/static/**") //
                .addResourceLocations("/public/") //
                .resourceChain(true) //
                .addResolver(new VersionResourceResolver().addContentVersionStrategy("/**"));
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(totpRequiredInterceptor);
    }

    @Override
    public void addCorsMappings(@NonNull CorsRegistry registry) {
        // Configure CORS to allow frontend access from specific origins:
        // - http://localhost:5173 - Direct Vite dev server
        // - http://localhost:8081 - Nginx proxy with real IP
        // - http://localhost:8082 - Nginx proxy with User A's IP (10.0.0.10)
        // - http://localhost:8083 - Nginx proxy with Attacker's IP (10.0.0.99)
        //
        // Security note: In production, restrict this to actual domain names.
        // Allowing wildcard origins (*) would introduce security vulnerabilities.
        registry.addMapping("/api/**") //
                .allowedOrigins("http://localhost:5173", "http://localhost:8081", "http://localhost:8082",
                        "http://localhost:8083") //
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") //
                .allowedHeaders("*") // In production, consider restricting to needed headers
                .allowCredentials(true); // Allows cookies, required for session-based auth
    }
}