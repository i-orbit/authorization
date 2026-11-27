package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.LoginRequest;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.framework.core.utils.JsonUtils;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
public class CustomizedUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public CustomizedUsernamePasswordAuthenticationFilter(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            LoginAuthenticationTokenService tokenService,
            SecurityProperties properties,
            ObjectMapper objectMapper,
            LoginAuditLogPublisher auditLogPublisher) {
        super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login"));
        setAuthenticationManager(authenticationManager);
        setSecurityContextRepository(securityContextRepository);
        setAuthenticationSuccessHandler(new LoginAuthenticationSuccessHandler(tokenService, auditLogPublisher));
        setAuthenticationFailureHandler(new LoginAuthenticationFailureHandler(objectMapper, properties.isHideActualMessageOfUserLoginFailures(), auditLogPublisher));
    }

    static final String LOGIN_STARTED_AT_ATTRIBUTE = CustomizedUsernamePasswordAuthenticationFilter.class.getName() + ".startedAt";

    static final String LOGIN_USERNAME_ATTRIBUTE = CustomizedUsernamePasswordAuthenticationFilter.class.getName() + ".username";

    static final String LOGIN_PLATFORM_ATTRIBUTE = CustomizedUsernamePasswordAuthenticationFilter.class.getName() + ".platform";

    static final String LOGIN_FORCED_REPLACEMENT_ATTRIBUTE = CustomizedUsernamePasswordAuthenticationFilter.class.getName() + ".forcedReplacement";

    @Override
    public @Nullable Authentication attemptAuthentication(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        request.setAttribute(LOGIN_STARTED_AT_ATTRIBUTE, System.currentTimeMillis());
        LoginRequest body = LoginRequest.withHttpServletRequest(request);
        request.setAttribute(LOGIN_USERNAME_ATTRIBUTE, body.getUsername());
        request.setAttribute(LOGIN_PLATFORM_ATTRIBUTE, body.getPlatform());
        request.setAttribute(LOGIN_FORCED_REPLACEMENT_ATTRIBUTE, body.isForcedReplacement());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(body);
        return getAuthenticationManager().authenticate(authentication);
    }

    @Slf4j
    private record LoginAuthenticationSuccessHandler(LoginAuthenticationTokenService tokenService,
                                                     LoginAuditLogPublisher auditLogPublisher) implements AuthenticationSuccessHandler {

        @Override
        public void onAuthenticationSuccess(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull Authentication authentication) throws IOException, ServletException {
            UsernamePasswordAuthenticationToken loginAuthentication = (UsernamePasswordAuthenticationToken) authentication;
            loginAuthentication.eraseCredentials();
            // 验证码已消费，不再写入登录会话
            loginAuthentication.getAdditionalParameters().remove(UsernamePasswordAuthenticationToken.PARAMETER_NAME_CAPTCHA_ID);
            loginAuthentication.getAdditionalParameters().remove(UsernamePasswordAuthenticationToken.PARAMETER_NAME_CAPTCHA_X);
            try {
                String sessionToken = tokenService.store(authentication);
                response.addHeader(HttpHeaders.SET_COOKIE,
                        LoginSessionCookie.create(request, sessionToken).toString());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                Map<String, Object> data = Map.of("authenticated", true);
                response.getWriter().println(JsonUtils.toJSONString(data));
                auditLogPublisher.success(request, authentication);

            } catch (RuntimeException e) {
                auditLogPublisher.failure(request, SecurityErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE);
                throw e;
            }
        }

    }

}
