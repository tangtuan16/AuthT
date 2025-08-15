package com.example.Auth.Services;

import com.example.Auth.DTO.RegisterRequest;
import com.example.Auth.DTO.UserRegisterDTO;
import com.example.Auth.Models.Role;
import com.example.Auth.Models.User;
import com.example.Auth.Repositories.RoleRepository;
import com.example.Auth.Repositories.UserRepository;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Set;

@Service
@AllArgsConstructor

public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserRegisterDTO register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username is already in use");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email is already in use");
        }

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(defaultRole))
                .build();

        User savedUser = userRepository.save(user);

        return UserRegisterDTO.builder()
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .roles("ROLE_USER")
                .build();
    }

}
