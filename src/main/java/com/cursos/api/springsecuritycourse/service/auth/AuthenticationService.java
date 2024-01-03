package com.cursos.api.springsecuritycourse.service.auth;

import com.cursos.api.springsecuritycourse.dto.RegisteredUser;
import com.cursos.api.springsecuritycourse.dto.SaveUser;
import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationRequest;
import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationResponse;
import com.cursos.api.springsecuritycourse.exception.ObjectNotFoundException;
import com.cursos.api.springsecuritycourse.persistence.entity.security.JwtToken;
import com.cursos.api.springsecuritycourse.persistence.entity.security.User;
import com.cursos.api.springsecuritycourse.persistence.repository.security.JwtTokenRepository;
import com.cursos.api.springsecuritycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthenticationService {

    @Autowired private UserService userService;
    @Autowired private JwtService jwtService;
    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private JwtTokenRepository jwtRepository;
    public RegisteredUser registerOneCustomer(SaveUser newUser) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        User user = this.userService.registerOneCustomer(newUser);
        String jwt = this.jwtService.generateToken(user, generateExtraClaims(user));
        this.saveUserToken(jwt, user);
        RegisteredUser userDto = new RegisteredUser();
        userDto.setId(user.getId());
        userDto.setName(user.getName());
        userDto.setUsername(user.getUsername());
        userDto.setRole(user.getRole().getName());

        userDto.setJwt(jwt);

        return userDto;
    }

    private Map<String, Object> generateExtraClaims(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("name", user.getName());
        extraClaims.put("role", user.getRole().getName());
        extraClaims.put("authorities", user.getAuthorities());
        return extraClaims;
    }

    public AuthenticationResponse login(AuthenticationRequest authRequest) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(),
                authRequest.getPassword()
        );
        this.authenticationManager.authenticate(authentication);

        UserDetails user = this.userService.findOneByUsername(authRequest.getUsername()).get();
        String jwt = this.jwtService.generateToken(user, generateExtraClaims((User)user));
        this.saveUserToken(jwt, (User) user);
        AuthenticationResponse res = new AuthenticationResponse();
        res.setJwt(jwt);
        return res;
    }


    private void saveUserToken(String jwt, User user) {
        JwtToken token = new JwtToken();
        token.setToken(jwt);
        token.setUser(user);
        token.setExpiration(jwtService.extractExpiration(jwt));
        token.setValid(true);

        jwtRepository.save(token);

    }

    public boolean validateToken(String jwt) {
        try {
            this.jwtService.extractUsername(jwt);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return  false;
        }
    }

    public User findLoggedUser() {
        UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        String username = (String) auth.getPrincipal();
        System.out.println(username);
        return this.userService.findOneByUsername(username).orElseThrow(() -> new ObjectNotFoundException("User not found. Username: " + username));

    }

    public void logout(HttpServletRequest request) {
        String jwt = this.jwtService.extractJwtFromRequest(request);
        if (jwt == null || !StringUtils.hasText(jwt)) return;
        Optional<JwtToken> token = this.jwtRepository.findByToken(jwt);
        if (token.isPresent() && token.get().isValid()) {
            token.get().setValid(false);
            this.jwtRepository.save(token.get());
        }
    }
}
