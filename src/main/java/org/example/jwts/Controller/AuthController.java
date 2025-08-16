package org.example.jwts.Controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.jwts.DTO.ApiResponse;
import org.example.jwts.DTO.AuthRequest;
import org.example.jwts.DTO.RefreshRequest;
import org.example.jwts.DTO.RegisterRequest;
import org.example.jwts.Service.AuthService;
import org.example.jwts.Service.CustomUserDetailsService;
import org.example.jwts.Service.EmailService;
import org.example.jwts.Service.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final EmailService emailService;
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        authService.register(registerRequest);
        return ApiResponse.success(null, HttpStatus.CREATED.value(), "Registration successful! Check your email to verify your account.", null);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Map<String, String>>> login(@Valid @RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        var user = (UserDetails) authentication.getPrincipal();
        String access = jwtService.generateAccessToken(user, new HashMap<>());
        String refresh = jwtService.generateRefreshToken(user);
        Map<String, String> data = new HashMap<>();
        data.put("accessToken", access);
        data.put("refreshToken", refresh);

        return ApiResponse.success(data, HttpStatus.OK.value(), "Success", null);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        ResponseEntity<?> userRegisterDTO = authService.verifyEmail(token);
        return ApiResponse.success(userRegisterDTO.getBody(), HttpStatus.OK.value(), "Success", null);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<Map<String, String>>> refresh(@Valid @RequestBody RefreshRequest request) {
        // Verify refresh token; nếu hợp lệ → cấp access token mới
        String username = jwtService.extractUsername(request.getRefreshToken());
        var user = userDetailsService.loadUserByUsername(username);
        if (!jwtService.validateToken(request.getRefreshToken(), user)) {
            return ResponseEntity.status(401).build();
        }

        String newAccess = jwtService.generateAccessToken(user, null);
        // tuỳ chiến lược: có thể rotate refresh
        String newRefresh = request.getRefreshToken();
        Map<String, String> data = new HashMap<>();
        data.put("accessToken", newAccess);
        data.put("refreshToken", newRefresh);

        return ApiResponse.success(data, 200, "Success", null);
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(auth == null ? null : auth.getPrincipal());
    }
}
