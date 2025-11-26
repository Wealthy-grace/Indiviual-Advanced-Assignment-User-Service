package com.example.userservice.security.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Spring Security Configuration for Keycloak JWT Token Validation
 *
 * FIXED VERSION:
 * - Handles role prefixes correctly (no duplicate ROLE_ROLE_STUDENT)
 * - Properly maps Keycloak roles to Spring Security authorities
 * - Uses preferred_username from JWT as principal
 * - Allows unauthenticated access to actuator health endpoints for Kubernetes probes
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        // CRITICAL: Actuator health endpoints for Kubernetes probes
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/actuator/health/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/actuator/info").permitAll()
                        .requestMatchers("/actuator/metrics/**").permitAll()
                        .requestMatchers("/actuator/prometheus").permitAll()

                        // Public endpoints - anyone can access
                        .requestMatchers(
                                "/api/auth/signup",
                                "/api/auth/login",
                                "/api/auth/health",
                                "/api/auth/keycloak-config",
                                "/api/auth/user/{username}",
                                "/api/auth/logout",
                                "/api/test/**",
                                "/api/circuit-breaker/**"
                        ).permitAll()

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

    // Convert Keycloak JWT to Spring Security Authentication Token
    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter());

        // Use preferred_username as the principal name (Keycloak default)
        // If not available, fallback to sub (subject/user ID)
        converter.setPrincipalClaimName("preferred_username");

        return converter;
    }


    @Bean
    public Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter() {
        return jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            // Extract roles from realm_access claim
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) realmAccess.get("roles");

                // Map each role to an authority with correct prefix handling
                authorities = roles.stream()
                        .map(this::mapRoleToAuthority)
                        .collect(Collectors.toList());
            }

            return authorities;
        };
    }

    // Map Keycloak roles to Spring Security authorities
    private GrantedAuthority mapRoleToAuthority(String role) {
        // If role already starts with "ROLE_", use it as-is (don't add another ROLE_)
        if (role.startsWith("ROLE_")) {
            return new SimpleGrantedAuthority(role);
        }

        // Standard Keycloak internal roles - use as-is without ROLE_ prefix
        if (role.startsWith("default-roles-") ||
                role.equals("offline_access") ||
                role.equals("uma_authorization")) {
            return new SimpleGrantedAuthority(role);
        }

        // Custom application roles - add ROLE_ prefix
        // This handles cases like "ADMIN" or "USER" without the prefix
        return new SimpleGrantedAuthority("ROLE_" + role);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}