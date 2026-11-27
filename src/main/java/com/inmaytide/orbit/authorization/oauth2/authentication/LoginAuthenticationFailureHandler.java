package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.framework.security.AuthenticationErrorCodeResolver;
import com.inmaytide.orbit.framework.security.ProblemDetailsWriter;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Converts Spring Security authentication failures into the Orbit API error format.
 *
 * @author inmaytide
 * @since 2026/11/20
 */
@Slf4j
final class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    private final boolean hideActualMessageOfUserLoginFailures;

    private final LoginAuditLogPublisher auditLogPublisher;

    LoginAuthenticationFailureHandler(ObjectMapper objectMapper,
                                      boolean hideActualMessageOfUserLoginFailures,
                                      LoginAuditLogPublisher auditLogPublisher) {
        this.objectMapper = objectMapper;
        this.hideActualMessageOfUserLoginFailures = hideActualMessageOfUserLoginFailures;
        this.auditLogPublisher = auditLogPublisher;
    }

    @Override
    public void onAuthenticationFailure(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull AuthenticationException exception) throws IOException, ServletException {
        SecurityErrorCode errorCode = resolveErrorCode(exception);
        log.debug("Login authentication failed, {type: {}, errorCode: {}}", exception.getClass().getSimpleName(), errorCode.getCode(), exception);

        ProblemDetailsWriter.write(request, response, objectMapper, errorCode);
        auditLogPublisher.failure(request, errorCode);
    }

    SecurityErrorCode resolveErrorCode(@Nonnull AuthenticationException exception) {
        if (exception instanceof CaptchaVerificationException) {
            return SecurityErrorCode.CAPTCHA_INVALID;
        }
        if (hideActualMessageOfUserLoginFailures && exception instanceof UsernameNotFoundException) {
            return SecurityErrorCode.INVALID_CREDENTIALS;
        }
        if (exception instanceof UsernameNotFoundException) {
            return SecurityErrorCode.USER_NOT_FOUND;
        }
        return AuthenticationErrorCodeResolver.resolve(exception);
    }

}
