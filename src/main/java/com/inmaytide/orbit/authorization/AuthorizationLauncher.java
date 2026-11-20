package com.inmaytide.orbit.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@EnableCaching
@SpringBootApplication
public class AuthorizationLauncher {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationLauncher.class, args);
	}

}
