package org.security;

import org.security.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class SecuritySsoBApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecuritySsoBApplication.class, args);
    }

}
