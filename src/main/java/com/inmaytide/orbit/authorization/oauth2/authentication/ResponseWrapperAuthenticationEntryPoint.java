package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.configuration.ErrorCode;
import com.inmaytide.orbit.framework.core.domain.dto.ResponseWrapper;
import com.inmaytide.orbit.framework.core.utils.JsonUtils;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
@Slf4j
@RequiredArgsConstructor
public class ResponseWrapperAuthenticationEntryPoint implements AuthenticationEntryPoint, AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull AuthenticationException exception) throws IOException {
        ErrorCode errorCode = AuthenticationErrorCodeResolver.resolve(exception);
        log.debug("Authentication failed, {type: {}, errorCode: {}}", exception.getClass().getSimpleName(), errorCode.getCode(), exception);

        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        ResponseWrapper<Void> body = ResponseWrapper.failure(
                errorCode.getHttpStatus().value(),
                errorCode.getCode(),
                errorCode.getDescription()
        );
        response.getWriter().println(JsonUtils.toJSONString(objectMapper, body));
    }

    @Override
    public void onAuthenticationFailure(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull AuthenticationException exception) throws IOException {
        commence(request, response, exception);
    }

}
