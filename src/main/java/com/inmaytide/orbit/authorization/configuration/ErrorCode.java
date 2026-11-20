package com.inmaytide.orbit.authorization.configuration;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    USER_NOT_FOUND(HttpStatus.BAD_REQUEST, "USER_NOT_FOUND", "No user found with username/phone/employeeId/email"),
    INVALID_CREDENTIALS(HttpStatus.BAD_REQUEST, "INVALID_CREDENTIALS", "Invalid username or password"),
    ACCOUNT_LOCKED(HttpStatus.LOCKED, "ACCOUNT_LOCKED", "User account is locked"),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED", "User account is disabled"),
    ACCOUNT_EXPIRED(HttpStatus.FORBIDDEN, "ACCOUNT_EXPIRED", "User account has expired"),
    ACCOUNT_STATUS_INVALID(HttpStatus.FORBIDDEN, "ACCOUNT_STATUS_INVALID", "User account status is invalid"),
    CREDENTIALS_EXPIRED(HttpStatus.UNAUTHORIZED, "CREDENTIALS_EXPIRED", "User credentials have expired"),
    SESSION_CONFLICT(HttpStatus.CONFLICT, "SESSION_CONFLICT", "User is already logged in elsewhere"),
    AUTHENTICATION_SERVICE_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "AUTHENTICATION_SERVICE_UNAVAILABLE", "Authentication service is temporarily unavailable"),
    AUTHENTICATION_REQUIRED(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED", "Authentication is required"),
    OAUTH2_AUTHENTICATION_ERROR(HttpStatus.BAD_REQUEST, "OAUTH2_AUTHENTICATION_ERROR", "OAuth2 authentication failed"),
    AUTHENTICATION_FAILED(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_FAILED", "Authentication failed"),
    UNEXPECTED(HttpStatus.INTERNAL_SERVER_ERROR, "UNEXPECTED", "Unexpected error");

    private final HttpStatus httpStatus;

    private final String code;

    private final String description;

}
