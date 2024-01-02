package com.cursos.api.springsecuritycourse.config.security;

import com.cursos.api.springsecuritycourse.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.persistence.utils.RolePermission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
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
                .authorizeHttpRequests(req -> {
                    // Products endpoints
                    req.requestMatchers(HttpMethod.GET, "/products").hasAuthority(RolePermission.READ_ALL_PRODUCTS.name());
                    req.requestMatchers(HttpMethod.GET, "/products/{productId}").hasAuthority(RolePermission.READ_ONE_PRODUCT.name());
                    req.requestMatchers(HttpMethod.POST, "/products").hasAuthority(RolePermission.CREATE_ONE_PRODUCT.name());
                    req.requestMatchers(HttpMethod.GET, "/products/{productId}").hasAuthority(RolePermission.UPDATE_ONE_PRODUCT.name());
                    req.requestMatchers(HttpMethod.PUT).hasAuthority(RolePermission.DISABLE_ONE_PRODUCT.name());
                    //Category endpoints
                    req.requestMatchers(HttpMethod.GET, "/categories").hasAuthority(RolePermission.READ_ONE_CATEGORY.name());
                    req.requestMatchers(HttpMethod.GET, "/categories/{categoriesId}").hasAuthority(RolePermission.READ_ONE_CATEGORY.name());
                    req.requestMatchers(HttpMethod.POST, "/categories").hasAuthority(RolePermission.CREATE_ONE_CATEGORY.name());
                    req.requestMatchers(HttpMethod.GET, "/categories/{categoriesId}").hasAuthority(RolePermission.UPDATE_ONE_CATEGORY.name());
                    req.requestMatchers(HttpMethod.PUT).hasAuthority(RolePermission.DISABLE_ONE_CATEGORY.name());


                    //Public endpoints
                    req.requestMatchers(HttpMethod.POST, "/categories").permitAll();
                    req.requestMatchers(HttpMethod.POST, "/auth/authenticate").permitAll();
                    req.requestMatchers(HttpMethod.GET, "/auth/validate").permitAll();
                    req.anyRequest().authenticated();
                })
                .build();

        return filterChain;
    }
}
