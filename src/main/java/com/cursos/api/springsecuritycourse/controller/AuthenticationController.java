package com.cursos.api.springsecuritycourse.controller;

import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationRequest;
import com.cursos.api.springsecuritycourse.dto.auth.AuthenticationResponse;
import com.cursos.api.springsecuritycourse.persistence.entity.User;
import com.cursos.api.springsecuritycourse.service.auth.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PreAuthorize("permitAll")
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestParam String jwt) {
        boolean isValid = authenticationService.validateToken(jwt);
        return ResponseEntity.ok(isValid);
    }
    @PreAuthorize("permitAll")
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody @Valid AuthenticationRequest authenticationRequest) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        AuthenticationResponse res = authenticationService.login(authenticationRequest);

        return ResponseEntity.ok(res);
    }

    @PreAuthorize("hasAuthority('READ_MY_PROFILE')")
    @GetMapping("/profile")
    public ResponseEntity<User> findMyProfile() {
        User user = this.authenticationService.findLoggedUser();
        return ResponseEntity.ok(user);
    }
}
