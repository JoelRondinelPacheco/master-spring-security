package com.cursos.api.springsecuritycourse.config.security;

import com.cursos.api.springsecuritycourse.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.persistence.utils.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class HttpSecurityConfig {


    @Autowired private AuthenticationProvider daoAuthProvider;
    @Autowired private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        SecurityFilterChain filterChain = http
                .csrf(csrfConfig -> csrfConfig.disable())
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(daoAuthProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .authorizeHttpRequests(req -> {
//                    buildRequestMatcherV2(req);
//                })
                .build();

        return filterChain;
    }

    private static void buildRequestMatcher(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry req) {
        // Products endpoints
        req.requestMatchers(HttpMethod.GET, "/products")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.GET, "/products/{productId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.POST, "/products")
                .hasRole(Role.ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.PUT, "/products/{productId}/disable")
                .hasRole(Role.ADMINISTRATOR.name());
        //Category endpoints
        req.requestMatchers(HttpMethod.GET, "/categories")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.GET, "/categories/{categoriesId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.POST, "/categories")
                .hasRole(Role.ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.PUT, "/categories/{categoriesId}")
                .hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.PUT, "/categories/{categoriesId}/disabled")
                .hasRole(Role.ADMINISTRATOR.name());


        //My profile
        req.requestMatchers(HttpMethod.GET, "/auth/profile").hasAnyRole(Role.ADMINISTRATOR.name(), Role.ASSISTANT_ADMINISTRATOR.name(), Role.CUSTOMER.name());

        //Public endpoints
        req.requestMatchers(HttpMethod.POST, "/categories").permitAll();
        req.requestMatchers(HttpMethod.POST, "/auth/authenticate").permitAll();
        req.requestMatchers(HttpMethod.GET, "/auth/validate").permitAll();
        req.anyRequest().authenticated();
    }
    private static void buildRequestMatcherV2(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry req) {
        //Public endpoints
        req.requestMatchers(HttpMethod.POST, "/categories").permitAll();
        req.requestMatchers(HttpMethod.POST, "/auth/authenticate").permitAll();
        req.requestMatchers(HttpMethod.GET, "/auth/validate").permitAll();
        req.anyRequest().authenticated();
    }
}
