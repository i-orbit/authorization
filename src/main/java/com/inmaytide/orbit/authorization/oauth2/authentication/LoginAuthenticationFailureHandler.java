package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.configuration.ErrorCode;
import com.inmaytide.orbit.framework.core.domain.dto.ResponseWrapper;
import com.inmaytide.orbit.framework.core.utils.JsonUtils;
import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
        ErrorCode errorCode = resolveErrorCode(exception);
        log.debug("Login authentication failed, {type: {}, errorCode: {}}", exception.getClass().getSimpleName(), errorCode.getCode(), exception);

        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        ResponseWrapper<Void> body = ResponseWrapper.failure(errorCode.getHttpStatus().value(), errorCode.getCode(), errorCode.getDescription());
        response.getWriter().println(JsonUtils.toJSONString(objectMapper, body));
        auditLogPublisher.failure(request, errorCode);
    }

    ErrorCode resolveErrorCode(@Nonnull AuthenticationException exception) {
        if (hideActualMessageOfUserLoginFailures && exception instanceof UsernameNotFoundException) {
            return ErrorCode.INVALID_CREDENTIALS;
        }
        if (exception instanceof UsernameNotFoundException) {
            return ErrorCode.USER_NOT_FOUND;
        }
        return AuthenticationErrorCodeResolver.resolve(exception);
    }

}
