package com.cursos.api.springsecuritycourse.config.security.filter;

import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.JwtToken;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.persistence.repository.security.JwtTokenRepository;
import com.cursos.api.springsecuritycourse.service.UserService;
import com.cursos.api.springsecuritycourse.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired private JwtService jwtService;
    @Autowired private UserService userService;
    @Autowired private JwtTokenRepository jwtRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1. Obtenear auth header
        //2. Obtener token
        String jwt = this.jwtService.extractJwtFromRequest(request);
        System.out.println(jwt);
        if (jwt == null || !StringUtils.hasText(jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        //2.1 Obtener token no expirado y valido desde base de datos
        Optional<JwtToken> token = this.jwtRepository.findByToken(jwt);
        System.out.println(token.get());
        boolean isValid = this.validateToken(token);

        if (!isValid) {
            filterChain.doFilter(request, response);
            return;
        }

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

    private boolean validateToken(Optional<JwtToken> token) {
        if(!token.isPresent()) {
            System.out.println("token no existe, o no fue generado en nuesto sistema");
            return false;
        }

        JwtToken tokenOk = token.get();
        Date now = new Date(System.currentTimeMillis());

        boolean isValid = tokenOk.isValid() && tokenOk.getExpiration().after(now);

        if (!isValid) {
            System.out.println("Token invalido");
            this.updateTokenStatus(tokenOk);
        }

        return isValid;
    }

    private void updateTokenStatus(JwtToken token) {
        token.setValid(false);
        this.jwtRepository.save(token);
    }
}
