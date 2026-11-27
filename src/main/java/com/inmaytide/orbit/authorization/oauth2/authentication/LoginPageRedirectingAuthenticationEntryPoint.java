package com.inmaytide.orbit.authorization.oauth2.authentication;

import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * 浏览器访问授权端点且未登录时跳转登录页，其余端点仍返回统一的 ProblemDetails。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
public class LoginPageRedirectingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String AUTHORIZATION_ENDPOINT_SUFFIX = "/oauth2/authorize";

    private final String loginPageUri;

    private final AuthenticationEntryPoint delegate;

    public LoginPageRedirectingAuthenticationEntryPoint(String loginPageUri, AuthenticationEntryPoint delegate) {
        this.loginPageUri = loginPageUri;
        this.delegate = delegate;
    }

    @Override
    public void commence(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response,
                         @Nonnull AuthenticationException exception) throws IOException, ServletException {
        if (isAuthorizationEndpointRequest(request)) {
            response.sendRedirect(loginPageUri);
            return;
        }
        delegate.commence(request, response, exception);
    }

    private static boolean isAuthorizationEndpointRequest(HttpServletRequest request) {
        return "GET".equalsIgnoreCase(request.getMethod())
                && request.getRequestURI().endsWith(AUTHORIZATION_ENDPOINT_SUFFIX);
    }
}
