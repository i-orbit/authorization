package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.orbit.authorization.oauth2.authentication.*;
import com.inmaytide.orbit.authorization.oauth2.service.RedisOAuth2AuthorizationService;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import com.inmaytide.orbit.framework.security.domain.Robot;
import com.inmaytide.orbit.framework.security.domain.UserClientDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.io.IOException;
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
                                                       RedisOAuth2AuthorizationService authorizationService) {
        UsernamePasswordAuthenticationProvider provider = new UsernamePasswordAuthenticationProvider(
                userService, passwordEncoder, properties, authorizationService);
        return new ProviderManager(provider);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      RegisteredClientRepository clientRepository,
                                                                      OAuth2AuthorizationService authorizationService) throws Exception {
        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.with(authorizationServerConfigurer, c -> {
            c.tokenIntrospectionEndpoint(endpoint -> {
                endpoint.authenticationProvider(new CustomizedOAuth2TokenIntrospectionAuthenticationProvider(clientRepository, authorizationService));
                endpoint.introspectionResponseHandler(new CustomizedOAuth2TokenIntrospectionAuthenticationSuccessHandler());
            });
        });
        http.authorizeHttpRequests(authorize -> {
            authorize.anyRequest().authenticated();
        });
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher());
        http.exceptionHandling(exceptions -> {
                    exceptions.defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint("http://127.0.0.1:3000/login"),
                            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    );
                }
        );
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.headers(c -> c.httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain authenticationSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager, SecurityContextRepository securityContextRepository) throws Exception {
        return http.authorizeHttpRequests(authorize -> {
                            authorize.requestMatchers(HttpMethod.POST, "/login").permitAll()
                                    .anyRequest().authenticated();
                        }
                )
                .exceptionHandling(exceptions -> {
                    exceptions.authenticationEntryPoint(new ResponseWrapperAuthenticationEntryPoint());
                })
                .addFilterAt(new CustomizedUsernamePasswordAuthenticationFilter(authenticationManager, securityContextRepository), UsernamePasswordAuthenticationFilter.class)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        return new InMemoryRegisteredClientRepository(user(), robot(passwordEncoder));
    }

    private RegisteredClient user() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofSeconds(properties.getUserClient().getAccessTokenValiditySeconds()))
                .build();

        return RegisteredClient.withId(UserClientDetails.USER_CLIENT_ID)
                .clientId(properties.getUserClient().getClientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scopes(scopes -> scopes.addAll(properties.getUserClient().getScopes()))
                .redirectUri("http://localhost:5173/callback")
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
