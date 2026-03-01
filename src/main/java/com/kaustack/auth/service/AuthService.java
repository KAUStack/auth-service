package com.kaustack.auth.service;

import com.kaustack.auth.exception.ResourceNotFoundException;
import com.kaustack.auth.exception.UnauthorizedException;
import com.kaustack.auth.model.User;
import com.kaustack.auth.repository.UserRepository;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public User getCurrentUser(String token) {
        if (token == null || !jwtService.validateAccessToken(token)) {
            throw new UnauthorizedException("Invalid access token");
        }

        UUID userId = jwtService.extractUserId(token);
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    public String refreshToken(String token) {
        if (token == null || !jwtService.validateRefreshToken(token)) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        UUID userId = jwtService.extractUserId(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return jwtService.generateAccessToken(user);
    }
}
