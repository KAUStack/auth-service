package com.kaustack.auth.service;

import com.kaustack.auth.model.Gender;
import com.kaustack.auth.model.User;
import com.kaustack.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Transactional
    public User processOAuth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        return userRepository.findByEmail(email)
                .map(existingUser -> {
                    // Update user if needed
                    return existingUser;
                })
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .name(name)
                            .gender(Gender.UNKNOWN) // Default
                            .build();
                    return userRepository.save(newUser);
                });
    }
}
