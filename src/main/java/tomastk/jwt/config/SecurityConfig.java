package tomastk.jwt.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tomastk.jwt.jwtconfig.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor

public class SecurityConfig {
    private final AuthenticationProvider authProvider;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;


    // Insert the public urls here:
    String[] publicUrls = {
            "/auth/**",
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authRequest ->
                authRequest
                .requestMatchers(publicUrls).permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(sessionManager -> {
                sessionManager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            })
            .authenticationProvider(authProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .formLogin(Customizer.withDefaults())
                .build();
    }

}