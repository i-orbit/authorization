package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.framework.security.ResponseWrapperAuthenticationEntryPoint;
import com.inmaytide.orbit.framework.security.domain.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ResponseWrapperAuthenticationEntryPointTests {

    private final JsonMapper objectMapper = JsonMapper.builder().build();

    private ResponseWrapperAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        entryPoint = new ResponseWrapperAuthenticationEntryPoint(objectMapper);
    }

    @ParameterizedTest
    @MethodSource("authenticationFailures")
    void writesMappedErrorAsJsonWithMatchingHttpStatus(AuthenticationException exception,
                                                       ErrorCode expected) throws Exception {
        MockHttpServletResponse response = commence(exception);

        assertThat(response.getStatus()).isEqualTo(expected.getHttpStatus().value());
        assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getCharacterEncoding()).isEqualTo(StandardCharsets.UTF_8.name());

        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("status").asInt()).isEqualTo(expected.getHttpStatus().value());
        assertThat(body.get("errorCode").asString()).isEqualTo(expected.getCode());
        assertThat(body.get("description").asString()).isEqualTo(expected.getDescription());
    }

    @Test
    void resolvesKnownFailureFromAuthenticationExceptionCause() throws Exception {
        AuthenticationException exception = new AuthenticationException("authorization failed",
                new SessionAuthenticationException("already logged in")) {
        };

        MockHttpServletResponse response = commence(exception);

        assertThat(response.getStatus()).isEqualTo(ErrorCode.SESSION_CONFLICT.getHttpStatus().value());
        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("errorCode").asString()).isEqualTo(ErrorCode.SESSION_CONFLICT.getCode());
    }

    @Test
    void writesUnifiedResponseWhenUsedAsAuthenticationFailureHandler() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthenticationException("invalid_grant"));

        assertThat(response.getStatus()).isEqualTo(ErrorCode.OAUTH2_AUTHENTICATION_ERROR.getHttpStatus().value());
        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("errorCode").asString()).isEqualTo(ErrorCode.OAUTH2_AUTHENTICATION_ERROR.getCode());
    }

    private MockHttpServletResponse commence(AuthenticationException exception) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(new MockHttpServletRequest(), response, exception);
        return response;
    }

    private static Stream<Arguments> authenticationFailures() {
        return Stream.of(
                Arguments.of(new UsernameNotFoundException("not found"), ErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new BadCredentialsException("bad credentials"), ErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new CompromisedPasswordException("compromised"), ErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new LockedException("locked"), ErrorCode.ACCOUNT_LOCKED),
                Arguments.of(new DisabledException("disabled"), ErrorCode.ACCOUNT_DISABLED),
                Arguments.of(new AccountExpiredException("expired"), ErrorCode.ACCOUNT_EXPIRED),
                Arguments.of(new CredentialsExpiredException("expired"), ErrorCode.CREDENTIALS_EXPIRED),
                Arguments.of(new AccountStatusException("invalid") {
                }, ErrorCode.ACCOUNT_STATUS_INVALID),
                Arguments.of(new SessionAuthenticationException("conflict"), ErrorCode.SESSION_CONFLICT),
                Arguments.of(new InternalAuthenticationServiceException("unavailable"),
                        ErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new AuthenticationServiceException("unavailable"),
                        ErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new ProviderNotFoundException("unavailable"),
                        ErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new AuthenticationCredentialsNotFoundException("required"),
                        ErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new InsufficientAuthenticationException("required"),
                        ErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new PreAuthenticatedCredentialsNotFoundException("required"),
                        ErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new OAuth2AuthenticationException("invalid_request"),
                        ErrorCode.OAUTH2_AUTHENTICATION_ERROR),
                Arguments.of(new InvalidBearerTokenException("invalid_token"),
                        ErrorCode.OAUTH2_AUTHENTICATION_ERROR),
                Arguments.of(new RememberMeAuthenticationException("failed"),
                        ErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new NonceExpiredException("expired"), ErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new InvalidOneTimeTokenException("invalid"), ErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new AuthenticationException("unknown") {
                }, ErrorCode.AUTHENTICATION_FAILED)
        );
    }

}
