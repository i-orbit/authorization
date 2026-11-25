package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.orbit.authorization.oauth2.authentication.CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler;
import com.inmaytide.orbit.authorization.oauth2.authentication.LoginAuthenticationTokenFilter;
import com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationProvider;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import com.inmaytide.orbit.authorization.oauth2.token.OrbitOAuth2TokenClaimsCustomizer;
import com.inmaytide.orbit.authorization.service.TenantStatusService;
import com.inmaytide.orbit.authorization.service.UserActivityService;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.security.ResponseWrapperAuthenticationEntryPoint;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.Robot;
import com.inmaytide.orbit.framework.security.domain.UserClientDetails;
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

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@DependsOn({"applicationContextHolder"})
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    private final SecurityProperties properties;

    public AuthorizationServerConfiguration(SecurityProperties properties) {
        this.properties = properties;
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
                                                       TenantStatusService tenantStatusService) {
        UsernamePasswordAuthenticationProvider provider = new UsernamePasswordAuthenticationProvider(
                userService, passwordEncoder, properties, authorizationService, tenantStatusService);
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
        final ResponseWrapperAuthenticationEntryPoint authenticationErrorHandler = new ResponseWrapperAuthenticationEntryPoint(objectMapper);
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
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(authenticationErrorHandler));
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
        return new InMemoryRegisteredClientRepository(user(passwordEncoder), robot(passwordEncoder));
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenClaimsCustomizer() {
        return new OrbitOAuth2TokenClaimsCustomizer();
    }

    private RegisteredClient user(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofSeconds(properties.getUserClient().getAccessTokenValiditySeconds()))
                .build();

        return RegisteredClient.withId(UserClientDetails.USER_CLIENT_ID)
                .clientId(properties.getUserClient().getClientId())
                .clientSecret(passwordEncoder.encode(properties.getUserClient().getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                })
                .scopes(scopes -> scopes.addAll(properties.getUserClient().getScopes()))
                .redirectUris(uris -> uris.addAll(properties.getUserClient().getRedirectUris()))
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                .tokenSettings(tokenSettings)
                .build();
    }

    private RegisteredClient robot(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.of(15, ChronoUnit.MINUTES))
                .build();
        return RegisteredClient.withId(Robot.ROBOT_CLIENT_ID)
                .clientId(properties.getRobot().getUsername())
                .clientSecret(passwordEncoder.encode(properties.getRobot().getPassword()))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethods(consumer -> consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                .scope("system:administrator")
                .tokenSettings(tokenSettings)
                .build();
    }


}
