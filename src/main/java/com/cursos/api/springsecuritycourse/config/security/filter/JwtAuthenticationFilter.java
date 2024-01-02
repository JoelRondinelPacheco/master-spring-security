package com.cursos.api.springsecuritycourse.config.security.filter;

import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.User;
import com.cursos.api.springsecuritycourse.service.UserService;
import com.cursos.api.springsecuritycourse.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.UserDatabase;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired private JwtService jwtService;
    @Autowired private UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //1. Obtener encabezado http authorization
        String authorizationHeader = request.getHeader("Authorization");
        if (!StringUtils.hasText(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //2. Obtener JWT desde encabezado
        String jwt = authorizationHeader.split(" ")[1];
        //3. Obtener subject/username desde el token

        try {
            String username = this.jwtService.extractUsername(jwt);
            System.out.println(username);
            //4. Setear objeto authentication dentro de security context holder
            User user = this.userService.findOneByUsername(username).orElseThrow(() -> new ObjectNotFoundException("User not found. Username: " + username));
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    username, null, user.getAuthorities()
            );
            authToken.setDetails(new WebAuthenticationDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authToken);
            //5. Ejecutra el resto de filtros
            System.out.println(user.getId());
            filterChain.doFilter(request, response);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("EXPECIONS");
            System.out.println(e.getCause());
            System.out.println(e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }
    }
}
