package com.example.Auth.Controllers;

import com.example.Auth.DTO.LoginRequest;
import com.example.Auth.DTO.RegisterRequest;
import com.example.Auth.DTO.TokenResponse;
import com.example.Auth.Models.User;
import com.example.Auth.Repositories.UserRepository;
import com.example.Auth.Services.AuthService;
import com.example.Auth.Services.Jwts.RefreshTokenService;
import com.example.Auth.Services.TokenBlacklistService;
import com.example.Auth.Utils.ApiResponse;
import com.example.Auth.Services.Jwts.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> redisTemplate;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        String username = request.getUsernameOrEmail();
        String password = request.getPassword();
        String deviceInfo = httpRequest.getHeader("User-Agent");
        String ipAddress = httpRequest.getRemoteAddr();
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            User user = userRepository.findByUsername(username);
            String deviceId = deviceInfo.replaceAll("\\s+", "_");
            TokenResponse tokenResponse = authService.login(user, deviceId);
            String keyAccessExist = "access:" + user.getId() + ":" + deviceId;
            String keyRefreshExist = "refresh:" + user.getId() + ":" + deviceId;

            // Lấy token cũ (nếu có)
            String existAccessToken = (String) redisTemplate.opsForValue().get(keyAccessExist);
            String existRefreshToken = (String) redisTemplate.opsForValue().get(keyRefreshExist);

            // Cho token cũ vào Blacklist
            if (existAccessToken != null) {
                long expirationTimeAccess = jwtTokenProvider.getExpirationDuration(existAccessToken);
                tokenBlacklistService.blacklistToken(user.getId(), deviceId, "access", existAccessToken, expirationTimeAccess);
            }
            if (existRefreshToken != null) {
                long expirationTimeRefresh = jwtTokenProvider.getExpirationDuration(existRefreshToken);
                tokenBlacklistService.blacklistToken(user.getId(), deviceId, "refresh", existRefreshToken, expirationTimeRefresh);
            }
            redisTemplate.opsForValue().set(keyAccessExist, tokenResponse.getAccessToken(), Duration.ofMinutes(15));
            redisTemplate.opsForValue().set(keyRefreshExist, tokenResponse.getRefreshToken(), Duration.ofDays(7));
            return ResponseEntity.ok(Map.of(
                    "accessToken", tokenResponse.getAccessToken(),
                    "refreshToken", tokenResponse.getRefreshToken()
            ));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest httpRequest) {
        String accessToken = jwtTokenProvider.resolveToken(httpRequest);
        if (accessToken == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing access token"));
        }

        String username;
        try {
            username = jwtTokenProvider.getUsernameFromToken(accessToken);
        } catch (ExpiredJwtException e) {
            username = e.getClaims().getSubject();
        }

        String deviceInfo = httpRequest.getHeader("User-Agent");
        String deviceId = deviceInfo.replaceAll("\\s+", "_");

        User user = userRepository.findByUsername(username);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "User not found"));
        }

        String keyRefresh = "refresh:" + user.getId() + ":" + deviceId;
        String refreshToken = (String) redisTemplate.opsForValue().get(keyRefresh);

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No refresh token found"));
        }

        if (tokenBlacklistService.isBlacklisted(user.getId(), deviceId, "refresh", refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token is blacklisted"));
        }

        TokenResponse tokenResponse = authService.refresh(refreshToken, deviceInfo, httpRequest.getRemoteAddr());

        long expOldAccess = jwtTokenProvider.getExpirationDuration(accessToken);
        long expOldRefresh = jwtTokenProvider.getExpirationDuration(refreshToken);
        tokenBlacklistService.blacklistToken(user.getId(), deviceId, "access", accessToken, expOldAccess);
        tokenBlacklistService.blacklistToken(user.getId(), deviceId, "refresh", refreshToken, expOldRefresh);

        redisTemplate.opsForValue().set("access:" + user.getId() + ":" + deviceId,
                tokenResponse.getAccessToken(), Duration.ofMinutes(15));
        redisTemplate.opsForValue().set("refresh:" + user.getId() + ":" + deviceId,
                tokenResponse.getRefreshToken(), Duration.ofDays(7));

        return ResponseEntity.ok(Map.of(
                "accessToken", tokenResponse.getAccessToken(),
                "refreshToken", tokenResponse.getRefreshToken()
        ));
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logoutRedis(@RequestHeader(value = "Authorization", required = false) String authHeader, Principal principal, HttpServletRequest httpRequest) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Authorization header is missing or invalid");
        }
        String token = authHeader.substring(7);
        long userId = jwtTokenProvider.extractUserId(token);
        String deviceId = httpRequest.getHeader("User-Agent").replaceAll("\\s+", "_");
        log.info("user id: {} device id: {}", userId, deviceId);
        String keyAccessExist = "access:" + userId + ":" + deviceId;
        String keyRefreshExist = "refresh:" + userId + ":" + deviceId;
        String accessToken = redisTemplate.opsForValue().get(keyAccessExist).toString();
        String refreshToken = redisTemplate.opsForValue().get(keyRefreshExist).toString();
        long expirationTime = jwtTokenProvider.getExpirationDuration(token);
        if (expirationTime <= 0) {
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST).body("Token already expired");
        }
        String existAccessToken = (String) redisTemplate.opsForValue().get(keyAccessExist);
        String existRefreshToken = (String) redisTemplate.opsForValue().get(keyRefreshExist);
        // Cho token cũ vào Blacklist
        if (existAccessToken != null) {
            long expirationTimeAccess = jwtTokenProvider.getExpirationDuration(existAccessToken);
            tokenBlacklistService.blacklistToken(userId, deviceId, "access", existAccessToken, expirationTimeAccess);
        }
        if (existRefreshToken != null) {
            long expirationTimeRefresh = jwtTokenProvider.getExpirationDuration(existRefreshToken);
            tokenBlacklistService.blacklistToken(userId, deviceId, "refresh", existRefreshToken, expirationTimeRefresh);
        }
        return ResponseEntity.ok("Logged out successfully (token added to Redis blacklist)");
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(HttpServletRequest request) {
        try {
            String accessToken = jwtTokenProvider.resolveToken(request);
            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Thiếu hoặc sai Authorization header"));
            }

            Long userId = jwtTokenProvider.extractUserId(accessToken);
            if (userId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token không hợp lệ"));
            }

            Set<String> accessKeys = redisTemplate.keys("access:" + userId + ":*");
            Set<String> refreshKeys = redisTemplate.keys("refresh:" + userId + ":*");

            if (accessKeys != null) {
                for (String key : accessKeys) {
                    String deviceId = key.split(":")[2];
                    String token = (String) redisTemplate.opsForValue().get(key);
                    if (token != null) {
                        long exp = jwtTokenProvider.getExpirationDuration(token);
                        tokenBlacklistService.blacklistToken(userId, deviceId, "access", token, exp);
                    }
                    redisTemplate.delete(key);
                }
            }

            if (refreshKeys != null) {
                for (String key : refreshKeys) {
                    String deviceId = key.split(":")[2];
                    String token = (String) redisTemplate.opsForValue().get(key);
                    if (token != null) {
                        long exp = jwtTokenProvider.getExpirationDuration(token);
                        tokenBlacklistService.blacklistToken(userId, deviceId, "refresh", token, exp);
                    }
                    redisTemplate.delete(key);
                }
            }

            log.info("User {} đã đăng xuất khỏi tất cả thiết bị", userId);
            return ResponseEntity.ok(Map.of("message", "Đã đăng xuất khỏi tất cả thiết bị"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
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
