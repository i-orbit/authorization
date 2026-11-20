package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.LoginRequest;
import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.io.IOException;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
public class CustomizedUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public CustomizedUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, SecurityContextRepository securityContextRepository) {
        super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login"));
        setAuthenticationManager(authenticationManager);
        setSecurityContextRepository(securityContextRepository);
        setAuthenticationSuccessHandler(new HttpMessageConverterAuthenticationSuccessHandler());
    }

    @Override
    public @Nullable Authentication attemptAuthentication(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        LoginRequest body = LoginRequest.withHttpServletRequest(request);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(body);
        return getAuthenticationManager().authenticate(authentication);
    }



}
