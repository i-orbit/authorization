package com.inmaytide.orbit.authorization.configuration;

import com.inmaytide.orbit.authorization.oauth2.authentication.CustomizedUsernamePasswordAuthenticationFilter;
import com.inmaytide.orbit.authorization.oauth2.authentication.LoginAuthenticationTokenFilter;
import com.inmaytide.orbit.authorization.oauth2.service.LoginAuthenticationTokenService;
import com.inmaytide.orbit.framework.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import tools.jackson.databind.ObjectMapper;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
@DependsOn({"applicationContextHolder"})
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authenticationManager,
                                                   SecurityContextRepository securityContextRepository,
                                                   ObjectMapper objectMapper,
                                                   LoginAuthenticationTokenService tokenService,
                                                   SecurityProperties properties) throws Exception {
        return http.authorizeHttpRequests(authorize -> {
                            authorize.requestMatchers(HttpMethod.POST, "/login").permitAll()
                                    .anyRequest().authenticated();
                        }
                )
                .addFilterAt(new CustomizedUsernamePasswordAuthenticationFilter(
                        authenticationManager, securityContextRepository, tokenService, properties, objectMapper
                ), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new LoginAuthenticationTokenFilter(tokenService), SecurityContextHolderFilter.class)
                .securityContext(context -> context.securityContextRepository(securityContextRepository))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

}
