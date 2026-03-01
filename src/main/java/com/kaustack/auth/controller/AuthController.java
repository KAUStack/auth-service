package com.kaustack.auth.controller;

import com.kaustack.auth.model.User;
import com.kaustack.auth.service.AuthService;
import com.kaustack.jwt.JwtUtils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import lombok.RequiredArgsConstructor;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;

@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtils jwtUtils;

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @GetMapping("/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(request.getContextPath() + "/oauth2/authorization/google");
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshToken(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response) {
        String newAccessToken = authService.refreshToken(refreshToken);

        ResponseCookie.ResponseCookieBuilder accessCookieBuilder = ResponseCookie.from("access_token", newAccessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(jwtUtils.extractMaxAge(newAccessToken));
        if (cookieDomain != null && !cookieDomain.isBlank()) {
            accessCookieBuilder.domain(cookieDomain);
        }
        ResponseCookie accessCookie = accessCookieBuilder.build();

        response.addHeader("Set-Cookie", accessCookie.toString());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser(
            @CookieValue(name = "access_token", required = false) String accessToken) {
        User user = authService.getCurrentUser(accessToken);
        return ResponseEntity.ok(user);
    }
}
