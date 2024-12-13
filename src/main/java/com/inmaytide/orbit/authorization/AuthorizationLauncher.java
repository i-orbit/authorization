package com.inmaytide.orbit.authorization;

import com.inmaytide.exception.web.BadRequestException;
import com.inmaytide.exception.web.mapper.PredictableExceptionMapper;
import com.inmaytide.exception.web.translator.PredictableExceptionTranslator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

@EnableCaching
@SpringBootApplication(scanBasePackages = {"com.inmaytide.orbit.authorization", "com.inmaytide.orbit.commons"})
public class AuthorizationLauncher {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationLauncher.class, args);
	}

	@Bean
	public PredictableExceptionTranslator predictableExceptionTranslator() {
		PredictableExceptionMapper mapper = new PredictableExceptionMapper();
		mapper.register(OAuth2AuthenticationException.class, BadRequestException.class);
		return new PredictableExceptionTranslator(mapper);
	}

}
