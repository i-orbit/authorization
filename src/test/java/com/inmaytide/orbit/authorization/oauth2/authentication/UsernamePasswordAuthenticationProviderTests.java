package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.LoginRequest;
import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import com.inmaytide.orbit.framework.core.enums.UserStatus;
import com.inmaytide.orbit.framework.core.utils.CodecUtils;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UsernamePasswordAuthenticationProviderTests {

    private static final String USER_ID = "user-1";

    private static final String PASSWORD_HASH = "password-hash";

    @Mock
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RedisOAuth2AuthorizationService authorizationService;

    private SecurityProperties properties;

    private UsernamePasswordAuthenticationProvider provider;

    private User user;

    @BeforeEach
    void setUp() {
        properties = new SecurityProperties();
        provider = new UsernamePasswordAuthenticationProvider(
                userService, passwordEncoder, properties, authorizationService);
        user = new User();
        user.setId(USER_ID);
        user.setUsername("alice");
        user.setPassword(PASSWORD_HASH);
        user.setStatus(UserStatus.NORMAL);
        when(userService.getByUsername("alice")).thenReturn(Optional.of(user));
        lenient().when(passwordEncoder.matches("secret", PASSWORD_HASH)).thenReturn(true);
    }

    @Test
    void authenticatesWithCorrectPasswordAndUserIdentity() {
        Authentication authentication = provider.authenticate(loginToken(false));

        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isEqualTo(USER_ID);
        assertThat(authentication.getCredentials()).isEqualTo(PASSWORD_HASH);
        verify(passwordEncoder).matches("secret", PASSWORD_HASH);
    }

    @Test
    void rejectsWrongPassword() {
        when(passwordEncoder.matches("secret", PASSWORD_HASH)).thenReturn(false);

        assertThatThrownBy(() -> provider.authenticate(loginToken(false)))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void rejectsPasswordThatCannotBeDecrypted() {
        LoginRequest request = new LoginRequest();
        request.setUsername("alice");
        request.setPassword("not-an-rsa-ciphertext");
        request.setPlatform(ClientPlatform.WEB);

        assertThatThrownBy(() -> provider.authenticate(new UsernamePasswordAuthenticationToken(request)))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Invalid username or password");
    }

    @Test
    void rejectsLockedAndDisabledUsers() {
        user.setStatus(UserStatus.LOCKED);
        assertThatThrownBy(() -> provider.authenticate(loginToken(false)))
                .isInstanceOf(LockedException.class);

        user.setStatus(UserStatus.DISABLED);
        assertThatThrownBy(() -> provider.authenticate(loginToken(false)))
                .isInstanceOf(DisabledException.class);
    }

    @Test
    void rejectsConcurrentLoginWhenReplacementIsNotForced() {
        when(authorizationService.findByPrincipalNameAndPlatform(USER_ID, ClientPlatform.WEB))
                .thenReturn(List.of(activeAuthorization()));

        assertThatThrownBy(() -> provider.authenticate(loginToken(false)))
                .isInstanceOf(SessionAuthenticationException.class)
                .hasMessage("User is already logged in elsewhere");
        verify(authorizationService, never()).remove(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void replacesExistingLoginWhenReplacementIsForced() {
        OAuth2Authorization existingAuthorization = activeAuthorization();
        when(authorizationService.findByPrincipalNameAndPlatform(USER_ID, ClientPlatform.WEB))
                .thenReturn(List.of(existingAuthorization));

        Authentication authentication = provider.authenticate(loginToken(true));

        assertThat(authentication.isAuthenticated()).isTrue();
        verify(authorizationService).remove(existingAuthorization);
    }

    @Test
    void allowsConcurrentLoginWhenConfigured() {
        properties.setAllowUsersToLoginSimultaneously(true);

        Authentication authentication = provider.authenticate(loginToken(false));

        assertThat(authentication.isAuthenticated()).isTrue();
        verify(authorizationService, never()).findByPrincipalNameAndPlatform(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any()
        );
    }

    private UsernamePasswordAuthenticationToken loginToken(boolean forceReplacement) {
        LoginRequest request = new LoginRequest();
        request.setUsername("alice");
        request.setPassword(CodecUtils.encrypt("secret"));
        request.setPlatform(ClientPlatform.WEB);
        request.setForcedReplacement(forceReplacement);
        return new UsernamePasswordAuthenticationToken(request);
    }

    private static OAuth2Authorization activeAuthorization() {
        RegisteredClient client = RegisteredClient.withId("client-registration")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .scope("openid")
                .build();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now().minusSeconds(5),
                Instant.now().plusSeconds(300)
        );
        return OAuth2Authorization.withRegisteredClient(client)
                .principalName(USER_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .accessToken(accessToken)
                .attribute(UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name())
                .build();
    }
}
