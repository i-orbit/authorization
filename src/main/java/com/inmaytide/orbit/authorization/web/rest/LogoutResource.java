package com.inmaytide.orbit.authorization.web.rest;

import com.inmaytide.orbit.authorization.oauth2.authentication.LoginSessionCookie;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 退出登录：注销登录会话及其关联的全部授权，并清除浏览器 Cookie。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
@Slf4j
@RestController
public class LogoutResource {

    private static final String BEARER_PREFIX = "Bearer ";

    private final RedisOAuth2AuthorizationService authorizationService;

    private final LoginAuthenticationTokenService tokenService;

    public LogoutResource(RedisOAuth2AuthorizationService authorizationService,
                          LoginAuthenticationTokenService tokenService) {
        this.authorizationService = authorizationService;
        this.tokenService = tokenService;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Nonnull HttpServletRequest request,
                                       @Nonnull HttpServletResponse response) {
        String sessionToken = resolveSessionToken(request);
        if (sessionToken != null) {
            authorizationService.removeBySessionToken(sessionToken);
            tokenService.remove(sessionToken);
            // 只有确实携带会话时才清除 Cookie，避免跨站 POST 清掉用户 Cookie
            response.addHeader(HttpHeaders.SET_COOKIE, LoginSessionCookie.clear(request).toString());
            log.info("【认证-退出登录】登录会话已注销");
        }
        return ResponseEntity.noContent().build();
    }

    private String resolveSessionToken(HttpServletRequest request) {
        String cookieToken = LoginSessionCookie.resolve(request);
        if (cookieToken != null) {
            return cookieToken;
        }
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String headerToken = authorization.substring(BEARER_PREFIX.length()).trim();
            if (!headerToken.isEmpty()) {
                return headerToken;
            }
        }
        return null;
    }
}
