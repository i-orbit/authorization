package com.inmaytide.orbit.authorization.web.rest;

import com.inmaytide.orbit.authorization.oauth2.authentication.LoginSessionCookie;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class LogoutResourceTests {

    private final RedisOAuth2AuthorizationService authorizationService =
            mock(RedisOAuth2AuthorizationService.class);

    private final LoginAuthenticationTokenService tokenService =
            mock(LoginAuthenticationTokenService.class);

    private final LogoutResource logoutResource = new LogoutResource(authorizationService, tokenService);

    @Test
    void removesSessionAuthorizationsAndClearsCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.setCookies(new Cookie(LoginSessionCookie.NAME, "session-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<Void> result = logoutResource.logout(request, response);

        verify(authorizationService).removeBySessionToken("session-token");
        verify(tokenService).remove("session-token");
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE))
                .contains(LoginSessionCookie.NAME + "=")
                .contains("Max-Age=0")
                .contains("HttpOnly");
    }

    @Test
    void doesNotTouchCookieWhenNoSessionIsPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<Void> result = logoutResource.logout(request, response);

        verify(authorizationService, never()).removeBySessionToken(org.mockito.ArgumentMatchers.anyString());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).isNull();
    }
}
