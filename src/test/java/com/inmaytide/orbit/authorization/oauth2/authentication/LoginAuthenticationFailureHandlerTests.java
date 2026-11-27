package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.json.ProblemDetailJacksonMixin;
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class LoginAuthenticationFailureHandlerTests {

    private final JsonMapper objectMapper = JsonMapper.builder()
            .addMixIn(ProblemDetail.class, ProblemDetailJacksonMixin.class)
            .build();

    private final LoginAuditLogPublisher auditLogPublisher = mock(LoginAuditLogPublisher.class);

    private LoginAuthenticationFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new LoginAuthenticationFailureHandler(objectMapper, true, auditLogPublisher);
    }

    @ParameterizedTest
    @MethodSource("authenticationFailures")
    void resolvesKnownAuthenticationFailures(AuthenticationException exception, SecurityErrorCode expected) {
        assertThat(handler.resolveErrorCode(exception)).isEqualTo(expected);
    }

    @Test
    void exposesUserNotFoundWhenFailureDetailsAreNotHidden() throws Exception {
        handler = new LoginAuthenticationFailureHandler(objectMapper, false, auditLogPublisher);

        MockHttpServletResponse response = handle(new UsernameNotFoundException("not found"));

        assertThat(response.getStatus()).isEqualTo(SecurityErrorCode.USER_NOT_FOUND.getHttpStatus().value());
        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("code").asString()).isEqualTo(SecurityErrorCode.USER_NOT_FOUND.getCode());
    }

    @Test
    void writesMappedErrorAsProblemDetailsWithMatchingHttpStatus() throws Exception {
        MockHttpServletResponse response = handle(new SessionAuthenticationException("already logged in"));

        assertThat(response.getStatus()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getHttpStatus().value());
        assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(response.getCharacterEncoding()).isEqualTo(StandardCharsets.UTF_8.name());

        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("status").asInt()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getHttpStatus().value());
        assertThat(body.get("title").asString()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getHttpStatus().getReasonPhrase());
        assertThat(body.get("detail").asString()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getDescription());
        assertThat(body.get("code").asString()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getCode());
    }

    private MockHttpServletResponse handle(AuthenticationException exception) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(new MockHttpServletRequest(), response, exception);
        return response;
    }

    private static Stream<Arguments> authenticationFailures() {
        return Stream.of(
                Arguments.of(new UsernameNotFoundException("not found"), SecurityErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new BadCredentialsException("bad credentials"), SecurityErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new CaptchaVerificationException("captcha"), SecurityErrorCode.CAPTCHA_INVALID),
                Arguments.of(new LockedException("locked"), SecurityErrorCode.ACCOUNT_LOCKED),
                Arguments.of(new DisabledException("disabled"), SecurityErrorCode.ACCOUNT_DISABLED),
                Arguments.of(new AccountExpiredException("expired"), SecurityErrorCode.ACCOUNT_EXPIRED),
                Arguments.of(new CredentialsExpiredException("expired"), SecurityErrorCode.CREDENTIALS_EXPIRED),
                Arguments.of(new AccountStatusException("invalid") {
                }, SecurityErrorCode.ACCOUNT_STATUS_INVALID),
                Arguments.of(new SessionAuthenticationException("conflict"), SecurityErrorCode.SESSION_CONFLICT),
                Arguments.of(new InternalAuthenticationServiceException("unavailable"),
                        SecurityErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new AuthenticationServiceException("unavailable"),
                        SecurityErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new ProviderNotFoundException("unavailable"),
                        SecurityErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new AuthenticationCredentialsNotFoundException("required"),
                        SecurityErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new InsufficientAuthenticationException("required"),
                        SecurityErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new OAuth2AuthenticationException("invalid_request"),
                        SecurityErrorCode.OAUTH2_AUTHENTICATION_ERROR),
                Arguments.of(new RememberMeAuthenticationException("failed"),
                        SecurityErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new NonceExpiredException("expired"), SecurityErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new AuthenticationException("unknown") {
                }, SecurityErrorCode.AUTHENTICATION_FAILED)
        );
    }
}
