package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginAuthenticationTokenFilterTests {

    private LoginAuthenticationTokenService tokenService;

    private LoginAuthenticationTokenFilter filter;

    @BeforeEach
    void setUp() {
        tokenService = mock(LoginAuthenticationTokenService.class);
        filter = new LoginAuthenticationTokenFilter(tokenService);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void restoresAuthenticationFromBearerTokenWithoutPersistingAContext() throws Exception {
        Authentication authentication = authentication();
        when(tokenService.find("login-token")).thenReturn(authentication);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer login-token");

        AtomicReference<Authentication> requestAuthentication = new AtomicReference<>();
        FilterChain filterChain = (req, res) -> requestAuthentication.set(
                SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        assertThat(requestAuthentication.get()).isSameAs(authentication);
        assertThat(request.getSession(false)).isNull();
    }

    @Test
    void restoresPrincipalBeforeAuthorizationCodeRequestConversion() throws Exception {
        Authentication authentication = authentication();
        when(tokenService.find("login-token")).thenReturn(authentication);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/authorize");
        request.setScheme("http");
        request.setServerName("127.0.0.1");
        request.setServerPort(30703);
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer login-token");
        request.addParameter("response_type", "code");
        request.addParameter("client_id", "orbit");
        request.addParameter("redirect_uri", "http://127.0.0.1:3000");
        request.addParameter("scope", "profile");

        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return "http://127.0.0.1:30703";
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return AuthorizationServerSettings.builder().build();
            }
        });
        AtomicReference<Authentication> authorizationPrincipal = new AtomicReference<>();
        FilterChain filterChain = (req, res) -> {
            OAuth2AuthorizationCodeRequestAuthenticationToken converted =
                    (OAuth2AuthorizationCodeRequestAuthenticationToken)
                            new OAuth2AuthorizationCodeRequestAuthenticationConverter()
                                    .convert((MockHttpServletRequest) req);
            authorizationPrincipal.set((Authentication) converted.getPrincipal());
        };

        try {
            filter.doFilter(request, new MockHttpServletResponse(), filterChain);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }

        assertThat(authorizationPrincipal.get()).isSameAs(authentication);
    }

    @Test
    void restoresAuthenticationFromLoginSessionCookieAndRenewsIt() throws Exception {
        Authentication authentication = authentication();
        when(tokenService.find("cookie-token")).thenReturn(authentication);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(LoginSessionCookie.NAME, "cookie-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<Authentication> requestAuthentication = new AtomicReference<>();
        FilterChain filterChain = (req, res) -> requestAuthentication.set(
                SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(request, response, filterChain);

        assertThat(requestAuthentication.get()).isSameAs(authentication);
        verify(tokenService).renew("cookie-token");
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE))
                .contains(LoginSessionCookie.NAME + "=cookie-token")
                .contains("HttpOnly")
                .contains("SameSite=Lax");
    }

    @Test
    void ignoresRequestsWithoutBearerToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic credentials");
        AtomicReference<Authentication> requestAuthentication = new AtomicReference<>();
        FilterChain filterChain = (req, res) -> requestAuthentication.set(
                SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        assertThat(requestAuthentication.get()).isNull();
        verify(tokenService, never()).find(anyString());
    }

    @Test
    void leavesTheRequestUnauthenticatedWhenTheTokenDoesNotExist() throws Exception {
        when(tokenService.find("expired-token")).thenReturn(null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer expired-token");
        AtomicReference<Authentication> requestAuthentication = new AtomicReference<>();
        FilterChain filterChain = (req, res) -> requestAuthentication.set(
                SecurityContextHolder.getContext().getAuthentication());

        filter.doFilter(request, new MockHttpServletResponse(), filterChain);

        assertThat(requestAuthentication.get()).isNull();
        verify(tokenService).find("expired-token");
    }

    private static Authentication authentication() {
        return new UsernamePasswordAuthenticationToken(
                "user-1", "credentials", Map.of("platform", "WEB"), List.of());
    }
}
