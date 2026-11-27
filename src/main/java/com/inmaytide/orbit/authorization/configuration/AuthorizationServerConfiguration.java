package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.orbit.authorization.oauth2.authentication.CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler;
import com.inmaytide.orbit.authorization.oauth2.authentication.LoginAuthenticationTokenFilter;
import com.inmaytide.orbit.authorization.oauth2.authentication.LoginPageRedirectingAuthenticationEntryPoint;
import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationProvider;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import com.inmaytide.orbit.authorization.oauth2.token.OrbitOAuth2TokenClaimsCustomizer;
import com.inmaytide.orbit.authorization.service.CaptchaService;
import com.inmaytide.orbit.authorization.service.TenantStatusService;
import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.security.ProblemDetailsAccessDeniedHandler;
import com.inmaytide.orbit.framework.security.ProblemDetailsAuthenticationEntryPoint;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.AuthorizationClient;
import com.inmaytide.orbit.framework.security.domain.AuthorizationProperties;
import com.inmaytide.orbit.framework.security.domain.Robot;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@DependsOn({"applicationContextHolder"})
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    private final AuthorizationProperties authorizationProperties;

    private final Robot robot;

    private final AuthorizationClient webClient;

    private final AuthorizationClient introspectClient;

    public AuthorizationServerConfiguration(SecurityProperties properties) {
        this.authorizationProperties = properties.getAuthorization();
        this.robot = properties.getAuthorization().getRobot();
        this.webClient = properties.getAuthorization().getWebClient();
        this.introspectClient = properties.getAuthorization().getIntrospectClient();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserService userService,
                                                       PasswordEncoder passwordEncoder,
                                                       SecurityProperties properties,
                                                       RedisOAuth2AuthorizationService authorizationService,
                                                       TenantStatusService tenantStatusService,
                                                       CaptchaService captchaService) {
        UsernamePasswordAuthenticationProvider provider = new UsernamePasswordAuthenticationProvider(
                userService, passwordEncoder, properties, authorizationService, tenantStatusService, captchaService);
        return new ProviderManager(provider);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new NullSecurityContextRepository();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      LoginAuthenticationTokenService tokenService,
                                                                      SecurityContextRepository securityContextRepository,
                                                                      UserActivityService userActivityService,
                                                                      TenantStatusService tenantStatusService,
                                                                      ObjectMapper objectMapper) throws Exception {
        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        final ProblemDetailsAuthenticationEntryPoint authenticationErrorHandler = new ProblemDetailsAuthenticationEntryPoint(objectMapper);
        final ProblemDetailsAccessDeniedHandler accessDeniedHandler = new ProblemDetailsAccessDeniedHandler(objectMapper);
        http.with(authorizationServerConfigurer, c -> {
            c.clientAuthentication(endpoint -> endpoint.errorResponseHandler(authenticationErrorHandler));
            c.tokenEndpoint(endpoint -> endpoint.errorResponseHandler(authenticationErrorHandler));
            c.tokenIntrospectionEndpoint(endpoint -> {
                endpoint.introspectionResponseHandler(new CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler(userActivityService, tenantStatusService));
            });
        });
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());
        http.authorizeHttpRequests(authorize -> {
            authorize.anyRequest().authenticated();
        });
        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new LoginPageRedirectingAuthenticationEntryPoint(
                        authorizationProperties.getLoginPageUri(), authenticationErrorHandler))
                .accessDeniedHandler(accessDeniedHandler));
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.addFilterAfter(new LoginAuthenticationTokenFilter(tokenService), SecurityContextHolderFilter.class);
        http.securityContext(context -> context.securityContextRepository(securityContextRepository));
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.requestCache(AbstractHttpConfigurer::disable);
        http.headers(c -> c.httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable));
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        return new InMemoryRegisteredClientRepository(introspectClient(passwordEncoder), webClient(), robotClient(passwordEncoder));
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenClaimsCustomizer() {
        return new OrbitOAuth2TokenClaimsCustomizer();
    }

    private RegisteredClient introspectClient(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofSeconds(introspectClient.getAccessTokenValiditySeconds()))
                .build();

        return RegisteredClient.withId(introspectClient.getId())
                .clientId(introspectClient.getClientId())
                .clientSecret(passwordEncoder.encode(introspectClient.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                })
                .scopes(scopes -> scopes.addAll(introspectClient.getScopes()))
                .redirectUris(uris -> uris.addAll(introspectClient.getRedirectUris()))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(tokenSettings)
                .build();
    }

    /**
     * 浏览器 SPA 使用的公开客户端：授权码 + PKCE，不保存 client_secret。
     */
    private RegisteredClient webClient() {
        List<String> scopes = webClient.getScopes().isEmpty() ? introspectClient.getScopes() : webClient.getScopes();
        List<String> redirectUris = webClient.getRedirectUris().isEmpty() ? introspectClient.getRedirectUris() : webClient.getRedirectUris();

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofSeconds(webClient.getAccessTokenValiditySeconds()))
                .build();

        return RegisteredClient.withId(webClient.getId())
                .clientId(webClient.getClientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scopes(uris -> uris.addAll(scopes))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(tokenSettings)
                .build();
    }

    private RegisteredClient robotClient(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.of(15, ChronoUnit.MINUTES))
                .build();
        return RegisteredClient.withId(Robot.ROBOT_CLIENT_ID)
                .clientId(robot.getUsername())
                .clientSecret(passwordEncoder.encode(robot.getPassword()))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethods(consumer -> consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                .scope("system:administrator")
                .tokenSettings(tokenSettings)
                .build();
    }


}
