package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.configuration.ErrorCode;
import jakarta.annotation.Nonnull;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;

/**
 * Resolves Spring Security authentication failures to stable Orbit error codes.
 *
 * @author inmaytide
 * @since 2026/11/25
 */
final class AuthenticationErrorCodeResolver {

    private AuthenticationErrorCodeResolver() {
    }

    static ErrorCode resolve(@Nonnull AuthenticationException exception) {
        ErrorCode errorCode = resolveDirectly(exception);
        if (errorCode != null) {
            return errorCode;
        }

        Throwable previous = exception;
        Throwable current = exception.getCause();
        while (current != null && current != previous) {
            if (current instanceof AuthenticationException nested) {
                errorCode = resolveDirectly(nested);
                if (errorCode != null) {
                    return errorCode;
                }
            }
            previous = current;
            current = current.getCause();
        }
        return ErrorCode.AUTHENTICATION_FAILED;
    }

    private static ErrorCode resolveDirectly(AuthenticationException exception) {
        return switch (exception) {
            case UsernameNotFoundException _,
                 BadCredentialsException _,
                 CompromisedPasswordException _ -> ErrorCode.INVALID_CREDENTIALS;
            case LockedException _ -> ErrorCode.ACCOUNT_LOCKED;
            case DisabledException _ -> ErrorCode.ACCOUNT_DISABLED;
            case AccountExpiredException _ -> ErrorCode.ACCOUNT_EXPIRED;
            case CredentialsExpiredException _ -> ErrorCode.CREDENTIALS_EXPIRED;
            case AccountStatusException _ -> ErrorCode.ACCOUNT_STATUS_INVALID;
            case SessionAuthenticationException _ -> ErrorCode.SESSION_CONFLICT;
            case AuthenticationServiceException _,
                 ProviderNotFoundException _ -> ErrorCode.AUTHENTICATION_SERVICE_UNAVAILABLE;
            case AuthenticationCredentialsNotFoundException _,
                 InsufficientAuthenticationException _,
                 PreAuthenticatedCredentialsNotFoundException _ -> ErrorCode.AUTHENTICATION_REQUIRED;
            case OAuth2AuthenticationException _ -> ErrorCode.OAUTH2_AUTHENTICATION_ERROR;
            case RememberMeAuthenticationException _,
                 NonceExpiredException _,
                 InvalidOneTimeTokenException _ -> ErrorCode.AUTHENTICATION_FAILED;
            default -> null;
        };
    }

}
