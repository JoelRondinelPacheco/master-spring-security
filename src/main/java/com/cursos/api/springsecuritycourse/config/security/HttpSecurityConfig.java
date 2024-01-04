package com.cursos.api.springsecuritycourse.config.security;

import com.cursos.api.springsecuritycourse.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.config.security.handler.CustomAuthenticationEntryPoint;
import com.cursos.api.springsecuritycourse.persistence.utils.RoleEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled = true)
public class HttpSecurityConfig {


    @Autowired private AuthenticationProvider daoAuthProvider;
    @Autowired private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Autowired private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired private AuthorizationManager<RequestAuthorizationContext> authorizationManager;
    @Autowired private AccessDeniedHandler accessDeniedHandler;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        SecurityFilterChain filterChain = http
                .cors(withDefaults())
                .csrf(csrfConfig -> csrfConfig.disable())
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(daoAuthProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(req -> {
                    req.anyRequest().access(authorizationManager);
                })
                .exceptionHandling(exceptionConfig -> {
                    exceptionConfig.authenticationEntryPoint(customAuthenticationEntryPoint);
                    exceptionConfig.accessDeniedHandler(accessDeniedHandler);
                })
                .build();

        return filterChain;
    }

    @Profile({"local","dev"})
    @Bean
    CorsConfigurationSource defaultCorsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5500"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Profile("docker")
    @Bean
    CorsConfigurationSource dockerCorsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://client"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private static void buildRequestMatcher(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry req) {
        // Products endpoints
        req.requestMatchers(HttpMethod.GET, "/products")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.GET, "/products/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.POST, "/products")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.PUT, "/products/{productId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());
        req.requestMatchers(HttpMethod.PUT, "/products/{productId}/disable")
                .hasRole(RoleEnum.ADMINISTRATOR.name());
        //Category endpoints
        req.requestMatchers(HttpMethod.GET, "/categories")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.GET, "/categories/{categoriesId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.POST, "/categories")
                .hasRole(RoleEnum.ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.PUT, "/categories/{categoriesId}")
                .hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name());

        req.requestMatchers(HttpMethod.PUT, "/categories/{categoriesId}/disabled")
                .hasRole(RoleEnum.ADMINISTRATOR.name());


        //My profile
        req.requestMatchers(HttpMethod.GET, "/auth/profile").hasAnyRole(RoleEnum.ADMINISTRATOR.name(), RoleEnum.ASSISTANT_ADMINISTRATOR.name(), RoleEnum.CUSTOMER.name());

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
