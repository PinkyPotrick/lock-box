package com.lockbox.config;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import com.lockbox.dto.ResponseEntityDTO;

/**
 * Sets the HTTP status code based on the statusCode field in ResponseEntityDTO.
 */
@ControllerAdvice
public class ResponseStatusCodeAdvice implements ResponseBodyAdvice<Object> {
    @Override
    public boolean supports(@NonNull MethodParameter returnType,
            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return ResponseEntityDTO.class.isAssignableFrom(returnType.getParameterType());
    }

    @Override
    public Object beforeBodyWrite(@Nullable Object body, @NonNull MethodParameter returnType,
            @NonNull MediaType selectedContentType,
            @NonNull Class<? extends HttpMessageConverter<?>> selectedConverterType, @NonNull ServerHttpRequest request,
            @NonNull ServerHttpResponse response) {

        if (body instanceof ResponseEntityDTO<?>) {
            ResponseEntityDTO<?> responseDTO = (ResponseEntityDTO<?>) body;
            int statusCode = responseDTO.getStatusCode();

            if (statusCode != HttpStatus.OK.value()) {
                response.setStatusCode(HttpStatus.valueOf(statusCode));
            }
        }

        return body;
    }
}