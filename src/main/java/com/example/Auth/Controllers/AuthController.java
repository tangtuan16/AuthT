package com.example.Auth.Controllers;

import com.example.Auth.DTO.LoginRequest;
import com.example.Auth.DTO.RegisterRequest;
import com.example.Auth.DTO.TokenResponse;
import com.example.Auth.Models.CustomUserDetails;
import com.example.Auth.Models.User;
import com.example.Auth.Repositories.RoleRepository;
import com.example.Auth.Repositories.UserRepository;
import com.example.Auth.Services.AuthService;
import com.example.Auth.Services.Jwts.RefreshTokenService;
import com.example.Auth.Utils.ApiResponse;
import com.example.Auth.Services.Jwts.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.logging.LogFactory;
import org.springframework.data.jdbc.core.JdbcAggregateOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String username = request.getUsernameOrEmail();
        String password = request.getPassword();
        String deviceInfo = httpRequest.getHeader("User-Agent");
        String ipAddress = httpRequest.getRemoteAddr();

        try {
            // Xác thực username/password với Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            User user = userRepository.findByUsername(username);
            TokenResponse tokenResponse = authService.login(user, deviceInfo, ipAddress);
            return ResponseEntity.ok(Map.of(
                    "accessToken", tokenResponse.getAccessToken(),
                    "refreshToken", tokenResponse.getRefreshToken(),
                    "user", Map.of("id", user.getId(), "username", user.getUsername())
            ));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) {

        String refreshToken = request.get("refreshToken");
        if (refreshToken == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing refreshToken"));
        }

        try {
            String deviceInfo = httpRequest.getHeader("User-Agent");
            String ipAddress = httpRequest.getRemoteAddr();

            TokenResponse tokenResponse = authService.refresh(refreshToken, deviceInfo, ipAddress);

            return ResponseEntity.ok(Map.of(
                    "accessToken", tokenResponse.getAccessToken(),
                    "refreshToken", tokenResponse.getRefreshToken()
            ));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String accessToken = request.get("accessToken");
        String refreshToken = request.get("refreshToken");

        if (accessToken == null || refreshToken == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing token"));
        }

        try {
            authService.logout(accessToken, refreshToken, "User logout");
            return ResponseEntity.ok(Map.of("message", "Đăng xuất thành công"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@RequestBody Map<String, String> request) {
        String accessToken = request.get("accessToken");
        if (accessToken == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing accessToken"));
        }

        Long userId = jwtTokenProvider.extractUserId(accessToken);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token"));
        }

        userRepository.findById(userId).ifPresent(refreshTokenService::revokeAllTokensByUser);
        return ResponseEntity.ok(Map.of("message", "Đã đăng xuất khỏi tất cả thiết bị"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing Bearer token"));
        }

        String token = authHeader.substring(7);
        if (!jwtTokenProvider.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token"));
        }

        Long userId = jwtTokenProvider.extractUserId(token);
        return userRepository.findById(userId)
                .map(user -> ResponseEntity.ok(Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "email", user.getEmail()
                )))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "User not found")));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        authService.register(registerRequest);
        return ApiResponse.success(null, HttpStatus.CREATED.value(), "Registration successful! Check your email to verify your account.", null);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        ResponseEntity<?> userRegisterDTO = authService.verifyEmail(token);
        return ApiResponse.success(userRegisterDTO.getBody(), HttpStatus.OK.value(), "Success", null);
    }

}
