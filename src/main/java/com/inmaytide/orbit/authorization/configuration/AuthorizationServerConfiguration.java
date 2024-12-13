package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.exception.translator.ThrowableTranslator;
import com.inmaytide.exception.web.BadCredentialsException;
import com.inmaytide.exception.web.HttpResponseException;
import com.inmaytide.exception.web.translator.HttpExceptionTranslatorDelegator;
import com.inmaytide.orbit.authorization.oauth2.authentication.CustomizedOAuth2TokenIntrospectionAuthenticationProvider;
import com.inmaytide.orbit.authorization.oauth2.authentication.CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler;
import com.inmaytide.orbit.authorization.oauth2.authentication.OAuth2PasswordAuthenticationConverter;
import com.inmaytide.orbit.authorization.oauth2.authentication.OAuth2PasswordAuthenticationProvider;
import com.inmaytide.orbit.authorization.oauth2.service.DefaultUserDetailsService;
import com.inmaytide.orbit.authorization.oauth2.store.OAuth2AccessTokenStore;
import com.inmaytide.orbit.authorization.oauth2.store.OAuth2AuthorizationStore;
import com.inmaytide.orbit.authorization.oauth2.store.RedisOAuth2AccessTokenStore;
import com.inmaytide.orbit.authorization.oauth2.store.RedisOAuth2AuthorizationStore;
import com.inmaytide.orbit.commons.domain.OrbitClientDetails;
import com.inmaytide.orbit.commons.domain.Robot;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@DependsOn({"exceptionResolver", "applicationContextHolder"})
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    private final HandlerExceptionResolver exceptionResolver;

    private final ApplicationProperties properties;

    private final HttpExceptionTranslatorDelegator exceptionTranslatorDelegator;

    public AuthorizationServerConfiguration(HandlerExceptionResolver exceptionResolver, ApplicationProperties properties, HttpExceptionTranslatorDelegator exceptionTranslatorDelegator) {
        this.exceptionResolver = exceptionResolver;
        this.properties = properties;
        this.exceptionTranslatorDelegator = exceptionTranslatorDelegator;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationStore.class)
    public OAuth2AuthorizationStore authorizationStore(RedisConnectionFactory connectionFactory) {
        return new RedisOAuth2AuthorizationStore(connectionFactory);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AccessTokenStore.class)
    public OAuth2AccessTokenStore accessTokenStore() {
        return new RedisOAuth2AccessTokenStore();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public AuthenticationManager authenticationManager(DefaultUserDetailsService userDetailService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      RegisteredClientRepository clientRepository,
                                                                      OAuth2AuthorizationService authorizationService,
                                                                      AuthenticationManager authenticationManager) throws Exception {
        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.with(authorizationServerConfigurer, c -> {
            c.tokenEndpoint((endpoint) -> {
                endpoint.errorResponseHandler((req, res, ex) -> {
                    if (properties.isHideActualMessageOfUserLoginFailures()) {
                        HttpResponseException e = exceptionTranslatorDelegator.translate(ex).orElse(null);
                        if (e != null) {
                            if (Objects.equals(e.getCode(), ErrorCode.E_0x02100001.value()) || Objects.equals(e.getCode(), ErrorCode.E_0x02100006.value())) {
                                ex = new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), new com.inmaytide.exception.web.BadCredentialsException(ErrorCode.E_0x02100007));
                            }
                        }
                    }
                    exceptionResolver.resolveException(req, res, null, ex);
                });
                endpoint.accessTokenRequestConverter(new OAuth2PasswordAuthenticationConverter());
                endpoint.authenticationProvider(new OAuth2PasswordAuthenticationProvider(authenticationManager, authorizationService, properties));
            }).tokenIntrospectionEndpoint(endpoint -> {
                endpoint.errorResponseHandler((req, res, ex) -> exceptionResolver.resolveException(req, res, null, ex));
                endpoint.authenticationProvider(new CustomizedOAuth2TokenIntrospectionAuthenticationProvider(clientRepository, authorizationService));
                endpoint.introspectionResponseHandler(new CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler());
            }).clientAuthentication(customizer -> {
                customizer.errorResponseHandler((req, res, ex) -> exceptionResolver.resolveException(req, res, null, ex));
            });
        });
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.headers(c -> c.httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable));
        http.exceptionHandling(c -> {
            c.accessDeniedHandler((req, res, ex) -> exceptionResolver.resolveException(req, res, null, ex));
            c.authenticationEntryPoint((req, res, ex) -> exceptionResolver.resolveException(req, res, null, ex));
        });
        return http.build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        return new InMemoryRegisteredClientRepository(orbit(passwordEncoder), robot(passwordEncoder));
    }

    private RegisteredClient orbit(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.of(OrbitClientDetails.getInstance().getAccessTokenValiditySeconds(), ChronoUnit.SECONDS))
                .refreshTokenTimeToLive(Duration.of(OrbitClientDetails.getInstance().getRefreshTokenValiditySeconds(), ChronoUnit.SECONDS))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                .reuseRefreshTokens(true)
                .build();
        return RegisteredClient.withId(OrbitClientDetails.ORBIT_CLIENT_ID)
                .clientId(OrbitClientDetails.getInstance().getClientId())
                .clientSecret(passwordEncoder.encode(OrbitClientDetails.getInstance().getClientSecret()))
                .clientAuthenticationMethods(consumer -> {
                    consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                })
                .authorizationGrantTypes(grantTypes -> OrbitClientDetails.getInstance().getAuthorizedGrantTypes().stream().map(AuthorizationGrantType::new).forEach(grantTypes::add))
                .scopes(scopes -> scopes.addAll(OrbitClientDetails.getInstance().getScopes()))
                .tokenSettings(tokenSettings)
                .build();
    }

    private RegisteredClient robot(PasswordEncoder passwordEncoder) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.of(60, ChronoUnit.SECONDS))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                .reuseRefreshTokens(true)
                .build();
        return RegisteredClient.withId(Robot.ROBOT_CLIENT_ID)
                .clientId(Robot.getInstance().getLoginName())
                .clientSecret(passwordEncoder.encode(Robot.getInstance().getPassword()))
                .authorizationGrantType(new AuthorizationGrantType(Robot.ROBOT_GRANT_TYPE))
                .clientAuthenticationMethods(consumer -> {
                    consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    consumer.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                })
                .scope("all")
                .tokenSettings(tokenSettings)
                .build();
    }


}
