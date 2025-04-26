package org.example.socialmediabackend.controller;

import org.example.socialmediabackend.responses.LoginResponse;
import org.example.socialmediabackend.service.JwtService;
import org.example.socialmediabackend.service.OAuth2UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/oauth2")
public class OAuth2AuthController {

    private final OAuth2UserService oauth2UserService;
    private final JwtService jwtService;

    public OAuth2AuthController(OAuth2UserService oauth2UserService, JwtService jwtService) {
        this.oauth2UserService = oauth2UserService;
        this.jwtService = jwtService;
    }

    @GetMapping("/login/oauth2/code/google")
    public ResponseEntity<LoginResponse> googleCallback(@AuthenticationPrincipal OAuth2User oauth2User) {
        String email = oauth2User.getAttribute("email");
        if (email == null) {
            return ResponseEntity.badRequest().build();
        }

        String token = oauth2UserService.generateTokenForOAuth2User(email);
        LoginResponse loginResponse = new LoginResponse(token, jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }
}