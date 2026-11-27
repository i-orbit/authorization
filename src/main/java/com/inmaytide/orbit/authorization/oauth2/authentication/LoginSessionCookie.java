package com.inmaytide.orbit.authorization.oauth2.authentication;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * 浏览器授权码流程使用的登录会话 Cookie。
 * <p>
 * 登录成功后由授权服务器写入 HttpOnly Cookie，浏览器跳转 {@code /oauth2/authorize} 时自动携带，
 * 使授权服务器无需依赖 HttpSession 即可识别用户。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
public final class LoginSessionCookie {

    public static final String NAME = "orbit_login_session";

    private static final String SAME_SITE = "Lax";

    private static final String PATH = "/";

    /**
     * Cookie 只作为登录会话令牌的浏览器载体，真正的空闲超时由 Redis 登录会话 TTL 控制。
     * 这里保留较长的浏览器有效期，避免服务端已滑动续期而浏览器先丢弃 Cookie。
     */
    private static final Duration MAX_AGE = Duration.ofDays(7);

    private LoginSessionCookie() {
    }

    public static @Nullable String resolve(@Nonnull HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (NAME.equals(cookie.getName()) && StringUtils.hasText(cookie.getValue())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public static ResponseCookie create(@Nonnull HttpServletRequest request, @Nonnull String token) {
        return ResponseCookie.from(NAME, token)
                .httpOnly(true)
                .secure(isSecure(request))
                .sameSite(SAME_SITE)
                .path(PATH)
                .maxAge(MAX_AGE)
                .build();
    }

    public static ResponseCookie clear(@Nonnull HttpServletRequest request) {
        return ResponseCookie.from(NAME, "")
                .httpOnly(true)
                .secure(isSecure(request))
                .sameSite(SAME_SITE)
                .path(PATH)
                .maxAge(Duration.ZERO)
                .build();
    }

    private static boolean isSecure(HttpServletRequest request) {
        return request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
    }
}
