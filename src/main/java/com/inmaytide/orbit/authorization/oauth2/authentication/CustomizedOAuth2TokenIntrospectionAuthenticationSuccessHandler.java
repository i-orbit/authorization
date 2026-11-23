package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.framework.core.utils.HttpUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * @author inmaytide
 * @since 2024/4/23
 */
@RequiredArgsConstructor
public class CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<OAuth2TokenIntrospection> tokenIntrospectionHttpResponseConverter = new OAuth2TokenIntrospectionHttpMessageConverter();

    private final UserActivityService userActivityService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (OAuth2TokenIntrospectionAuthenticationToken) authentication;
        OAuth2TokenIntrospection tokenClaims = tokenIntrospectionAuthentication.getTokenClaims();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        this.tokenIntrospectionHttpResponseConverter.write(tokenClaims, null, httpResponse);

        if (tokenClaims.isActive()) {
            String ipAddress = HttpUtils.getClientIpAddress(request);
            Thread.ofVirtual().start(() -> userActivityService.cacheUserActivity(ipAddress, tokenClaims));
        }
    }
}
