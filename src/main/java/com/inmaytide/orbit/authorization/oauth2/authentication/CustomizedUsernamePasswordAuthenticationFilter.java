package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.LoginRequest;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.framework.core.domain.dto.ResponseWrapper;
import com.inmaytide.orbit.framework.core.utils.JsonUtils;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
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

    public CustomizedUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                          SecurityContextRepository securityContextRepository,
                                                          LoginAuthenticationTokenService tokenService,
                                                          SecurityProperties properties,
                                                          ObjectMapper objectMapper) {
        super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login"));
        setAuthenticationManager(authenticationManager);
        setSecurityContextRepository(securityContextRepository);
        setAuthenticationSuccessHandler(new LoginAuthenticationSuccessHandler(tokenService));
        setAuthenticationFailureHandler(new LoginAuthenticationFailureHandler(objectMapper, properties.isHideActualMessageOfUserLoginFailures()));
    }

    @Override
    public @Nullable Authentication attemptAuthentication(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        LoginRequest body = LoginRequest.withHttpServletRequest(request);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(body);
        return getAuthenticationManager().authenticate(authentication);
    }

    @Slf4j
    private record LoginAuthenticationSuccessHandler(LoginAuthenticationTokenService tokenService)
            implements AuthenticationSuccessHandler {

        @Override
        public void onAuthenticationSuccess(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull Authentication authentication) throws IOException, ServletException {
            ((UsernamePasswordAuthenticationToken) authentication).eraseCredentials();
            String accessToken = tokenService.store(authentication);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            Map<String, Object> data = Map.of("accessToken", accessToken, "tokenType", "Bearer");
            response.getWriter().println(JsonUtils.toJSONString(ResponseWrapper.success(data)));
        }

    }

}
