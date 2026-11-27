package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Restores a login authentication token into the current request context without a session.
 *
 * @author inmaytide
 * @since 2026/11/20
 */
@RequiredArgsConstructor
@Slf4j
public class LoginAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final LoginAuthenticationTokenService tokenService;

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request,
                                    @Nonnull HttpServletResponse response,
                                    @Nonnull FilterChain filterChain) throws ServletException, IOException {
        String headerToken = resolveBearerToken(request);
        String cookieToken = LoginSessionCookie.resolve(request);
        String token = headerToken != null ? headerToken : cookieToken;
        if (StringUtils.hasText(token)) {
            Authentication authentication = tokenService.find(token);
            if (authentication instanceof UsernamePasswordAuthenticationToken loginAuthentication
                    && authentication.isAuthenticated()) {
                loginAuthentication.setDetails(token);
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(loginAuthentication);
                SecurityContextHolder.setContext(context);
                tokenService.renew(token);
                if (headerToken == null && cookieToken != null) {
                    response.addHeader(HttpHeaders.SET_COOKIE,
                            LoginSessionCookie.create(request, token).toString());
                }
                log.debug("Login authentication token applied to the request SecurityContext");
            } else {
                log.debug("Login authentication token is invalid or expired");
            }
        }
        filterChain.doFilter(request, response);
    }

    private @Nullable String resolveBearerToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.startsWithIgnoreCase(authorization, BEARER_PREFIX)) {
            return null;
        }
        String token = authorization.substring(BEARER_PREFIX.length()).trim();
        return StringUtils.hasText(token) ? token : null;
    }
}
