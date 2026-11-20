package com.inmaytide.orbit.authorization.oauth2.authentication;

import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
@Slf4j
public class ResponseWrapperAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(@Nonnull HttpServletRequest request, @Nonnull  HttpServletResponse response, @Nonnull  AuthenticationException exception) throws IOException {
        log.error("errorrrr: ", exception);
        response.getWriter().println("111111");
    }

}
