package com.inmaytide.orbit.authorization.oauth2.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class LoginPageRedirectingAuthenticationEntryPointTests {

    private final AuthenticationEntryPoint delegate = mock(AuthenticationEntryPoint.class);

    private final LoginPageRedirectingAuthenticationEntryPoint entryPoint =
            new LoginPageRedirectingAuthenticationEntryPoint("/login", delegate);

    @Test
    void redirectsUnauthenticatedAuthorizationEndpointRequestsToTheLoginPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new InsufficientAuthenticationException("unauthorized"));

        assertThat(response.getRedirectedUrl()).isEqualTo("/login");
        verify(delegate, never()).commence(any(), any(), any());
    }

    @Test
    void delegatesNonAuthorizationEndpointRequests() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/introspect");
        MockHttpServletResponse response = new MockHttpServletResponse();
        InsufficientAuthenticationException exception = new InsufficientAuthenticationException("unauthorized");

        entryPoint.commence(request, response, exception);

        verify(delegate).commence(request, response, exception);
        assertThat(response.getRedirectedUrl()).isNull();
    }
}
