package com.example.userservice.security.Config;

import com.example.userservice.security.jwt.AuthEntryPointJwt;
import com.example.userservice.security.jwt.AuthTokenFilter;
import com.example.userservice.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize annotations
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final AuthEntryPointJwt unauthorizedHandler;
    private final JwtUtils jwtUtils;
    private final CustomUserDetailsService customUserDetailsService;

    // JWT authentication filter
    @Bean
    public AuthTokenFilter jwtTokenFilter() {
        return new AuthTokenFilter(jwtUtils, customUserDetailsService);
    }

    // Configure security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthTokenFilter jwtTokenFilter) throws Exception {

        http
                // Disable CSRF for stateless REST API
                .csrf(csrf -> csrf.disable())

                // Exception handling for unauthorized requests
                .exceptionHandling(handler -> handler
                        .authenticationEntryPoint(unauthorizedHandler))

                // Stateless session management (no sessions)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Role-based access control
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/signup").permitAll()
                        // Only ADMIN can access all users
                        .requestMatchers(HttpMethod.GET, "/api/auth/users").hasRole("ADMIN")
                        // Profile endpoints: any authenticated user
                        .requestMatchers("/api/auth/profile/**").authenticated()
                        // Default: require authentication for all other endpoints
                        .anyRequest().authenticated()
                );

        // Add JWT filter before username/password authentication
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // AuthenticationManager bean
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Password encoder for hashing passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
