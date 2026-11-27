package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.framework.security.ProblemDetailsAuthenticationEntryPoint;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import com.inmaytide.orbit.framework.security.domain.TenantStatusException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ProblemDetailsAuthenticationEntryPointTests {

    private final JsonMapper objectMapper = JsonMapper.builder()
            .addMixIn(ProblemDetail.class, ProblemDetailJacksonMixin.class)
            .build();

    private ProblemDetailsAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        entryPoint = new ProblemDetailsAuthenticationEntryPoint(objectMapper);
    }

    @ParameterizedTest
    @MethodSource("authenticationFailures")
    void writesMappedErrorAsProblemDetailsWithMatchingHttpStatus(AuthenticationException exception,
                                                                 SecurityErrorCode expected) throws Exception {
        MockHttpServletResponse response = commence(exception);

        assertThat(response.getStatus()).isEqualTo(expected.getHttpStatus().value());
        assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(response.getCharacterEncoding()).isEqualTo(StandardCharsets.UTF_8.name());

        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("status").asInt()).isEqualTo(expected.getHttpStatus().value());
        assertThat(body.get("title").asString()).isEqualTo(expected.getHttpStatus().getReasonPhrase());
        assertThat(body.get("detail").asString()).isEqualTo(expected.getDescription());
        assertThat(body.get("code").asString()).isEqualTo(expected.getCode());
    }

    @Test
    void resolvesKnownFailureFromAuthenticationExceptionCause() throws Exception {
        AuthenticationException exception = new AuthenticationException("authorization failed",
                new SessionAuthenticationException("already logged in")) {
        };

        MockHttpServletResponse response = commence(exception);

        assertThat(response.getStatus()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getHttpStatus().value());
        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("code").asString()).isEqualTo(SecurityErrorCode.SESSION_CONFLICT.getCode());
    }

    @Test
    void writesProblemDetailsWhenUsedAsAuthenticationFailureHandler() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthenticationException("invalid_grant"));

        assertThat(response.getStatus()).isEqualTo(SecurityErrorCode.OAUTH2_AUTHENTICATION_ERROR.getHttpStatus().value());
        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("code").asString()).isEqualTo(SecurityErrorCode.OAUTH2_AUTHENTICATION_ERROR.getCode());
    }

    private MockHttpServletResponse commence(AuthenticationException exception) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(new MockHttpServletRequest(), response, exception);
        return response;
    }

    private static Stream<Arguments> authenticationFailures() {
        return Stream.of(
                Arguments.of(new UsernameNotFoundException("not found"), SecurityErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new BadCredentialsException("bad credentials"), SecurityErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new CompromisedPasswordException("compromised"), SecurityErrorCode.INVALID_CREDENTIALS),
                Arguments.of(new LockedException("locked"), SecurityErrorCode.ACCOUNT_LOCKED),
                Arguments.of(new DisabledException("disabled"), SecurityErrorCode.ACCOUNT_DISABLED),
                Arguments.of(new AccountExpiredException("expired"), SecurityErrorCode.ACCOUNT_EXPIRED),
                Arguments.of(new CredentialsExpiredException("expired"), SecurityErrorCode.CREDENTIALS_EXPIRED),
                Arguments.of(new AccountStatusException("invalid") {
                }, SecurityErrorCode.ACCOUNT_STATUS_INVALID),
                Arguments.of(new SessionAuthenticationException("conflict"), SecurityErrorCode.SESSION_CONFLICT),
                Arguments.of(new TenantStatusException(SecurityErrorCode.TENANT_DISABLED, "disabled"),
                        SecurityErrorCode.TENANT_DISABLED),
                Arguments.of(new TenantStatusException(SecurityErrorCode.TENANT_EXPIRED, "expired"),
                        SecurityErrorCode.TENANT_EXPIRED),
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
                Arguments.of(new PreAuthenticatedCredentialsNotFoundException("required"),
                        SecurityErrorCode.AUTHENTICATION_REQUIRED),
                Arguments.of(new AuthenticationServiceException("introspection rejected",
                                new OAuth2IntrospectionException("introspection failed",
                                        new RestClientResponseException("Unauthorized", HttpStatus.UNAUTHORIZED,
                                                "Unauthorized", HttpHeaders.EMPTY, new byte[0],
                                                StandardCharsets.UTF_8))),
                        SecurityErrorCode.AUTHENTICATION_SERVICE_REJECTED),
                Arguments.of(new AuthenticationServiceException("introspection unreachable",
                                new OAuth2IntrospectionException("connection refused",
                                        new ResourceAccessException("Connection refused"))),
                        SecurityErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE),
                Arguments.of(new OAuth2AuthenticationException("invalid_request"),
                        SecurityErrorCode.OAUTH2_AUTHENTICATION_ERROR),
                Arguments.of(new InvalidBearerTokenException("invalid_token"),
                        SecurityErrorCode.OAUTH2_AUTHENTICATION_ERROR),
                Arguments.of(new RememberMeAuthenticationException("failed"),
                        SecurityErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new NonceExpiredException("expired"), SecurityErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new InvalidOneTimeTokenException("invalid"), SecurityErrorCode.AUTHENTICATION_FAILED),
                Arguments.of(new AuthenticationException("unknown") {
                }, SecurityErrorCode.AUTHENTICATION_FAILED)
        );
    }

}
