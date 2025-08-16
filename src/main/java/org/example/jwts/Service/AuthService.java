package org.example.jwts.Service;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.example.jwts.DTO.ApiResponse;
import org.example.jwts.DTO.RegisterRequest;
import org.example.jwts.Models.Role;
import org.example.jwts.Models.User;
import org.example.jwts.Models.VerificationToken;
import org.example.jwts.Repository.RoleRepository;
import org.example.jwts.Repository.UserRepository;
import org.example.jwts.Repository.VerificationTokenRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Service
@AllArgsConstructor

public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final VerificationTokenRepository tokenRepository;

    public void register(@Valid @RequestBody RegisterRequest request) {
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
                .enabled(false)
                .roles(Set.of(defaultRole))
                .build();

        User savedUser = userRepository.save(user);
        // tạo token xác thực
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .user(user)
                .build();

        tokenRepository.save(verificationToken);

        emailService.sendVerificationEmail(request.getEmail(), token);
        ;
    }

    public ResponseEntity<?> verifyEmail(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(user.getUsername());
        registerRequest.setEmail(user.getEmail());
        return ApiResponse.success(registerRequest, HttpStatus.CREATED.value(), "Verify Success!", null);
    }

}
