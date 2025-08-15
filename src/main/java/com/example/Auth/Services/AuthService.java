package com.example.Auth.Services;

import com.example.Auth.DTO.RegisterRequest;
import com.example.Auth.DTO.TokenResponse;
import com.example.Auth.DTO.UserRegisterDTO;
import com.example.Auth.Models.*;
import com.example.Auth.Repositories.*;
import com.example.Auth.Services.Jwts.JwtTokenProvider;
import com.example.Auth.Services.Jwts.RefreshTokenService;
import com.example.Auth.Utils.ApiResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Set;
import java.util.UUID;

import static com.example.Auth.DTO.UserRegisterDTO.maptoDTO;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final VerificationTokenRepository tokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtTokenProvider jwtProvider;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final TokenBlacklistService tokenBlacklistService;

    public TokenResponse login(User user, String deviceId) {
        String accessToken = jwtProvider.generateAccessToken(user, deviceId);
        String refreshToken = jwtProvider.generateRefreshToken(user, deviceId);
        Jws<Claims> refreshClaims = jwtProvider.parseToken(refreshToken);
        String refreshJti = refreshClaims.getBody().getId();

        LocalDateTime issuedAt = LocalDateTime.ofInstant(
                refreshClaims.getBody().getIssuedAt().toInstant(), ZoneId.systemDefault());
        LocalDateTime expiresAt = LocalDateTime.ofInstant(
                refreshClaims.getBody().getExpiration().toInstant(), ZoneId.systemDefault());

        return new TokenResponse(accessToken, refreshToken);

    }

    // Làm mới Access Token
    @Transactional
    public TokenResponse refresh(String refreshToken, String deviceInfo, String ipAddress) {
        try {
            Jws<Claims> claims = jwtProvider.parseToken(refreshToken);
            Long userId = Long.valueOf(claims.getBody().getSubject());
            String type = claims.getBody().get("type", String.class);
            if (!"refresh".equals(type)) {
                throw new RuntimeException("Sai định dạng token!");
            }

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại"));

            String deviceId = deviceInfo.replaceAll("\\s+", "_");

            if (tokenBlacklistService.isBlacklisted(user.getId(), deviceId, "refresh", refreshToken)) {
                throw new RuntimeException("Refresh token đã bị thu hồi!");
            }

            String keyRefresh = "refresh:" + user.getId() + ":" + deviceId;
            String refreshInRedis = (String) redisTemplate.opsForValue().get(keyRefresh);
            if (refreshInRedis == null || !refreshInRedis.equals(refreshToken)) {
                throw new RuntimeException("Refresh token không hợp lệ hoặc không khớp Redis!");
            }

            long expOldRefresh = jwtProvider.getExpirationDuration(refreshToken);
            tokenBlacklistService.blacklistToken(user.getId(), deviceId, "refresh", refreshToken, expOldRefresh);

            String newAccessToken = jwtProvider.generateAccessToken(user, deviceId);
            String newRefreshToken = jwtProvider.generateRefreshToken(user, deviceId);

            redisTemplate.opsForValue().set("access:" + user.getId() + ":" + deviceId,
                    newAccessToken, Duration.ofMinutes(15));
            redisTemplate.opsForValue().set("refresh:" + user.getId() + ":" + deviceId,
                    newRefreshToken, Duration.ofDays(7));

            log.info("🔄 Refresh token thành công cho userId={}, deviceId={}, ip={}", userId, deviceId, ipAddress);

            return new TokenResponse(newAccessToken, newRefreshToken);

        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Refresh token đã hết hạn!");
        } catch (JwtException e) {
            throw new RuntimeException("Refresh token không hợp lệ!");
        }
    }


    // Logout (revoke refresh token + blacklist access token)
    @Transactional
    public void logout(String accessToken, String refreshToken, String reason) {
        String jti = jwtProvider.extractJti(accessToken);
        Long userId = jwtProvider.extractUserId(accessToken);

        log.debug("Jti : {}", jti);
        log.debug("User id : {}", userId);
        if (jti != null && userId != null) {
            BlacklistedToken blacklisted = BlacklistedToken.builder()
                    .jti(jti)
                    .user(User.builder().id(userId).build())
                    .reason(reason)
                    .expiresAt(LocalDateTime.now().plusMinutes(10)) // TTL = AT còn lại
                    .build();
            blacklistedTokenRepository.save(blacklisted);
        }

        refreshTokenService.findByToken(refreshToken)
                .ifPresent(refreshTokenService::revokeToken);
    }

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
                .active(false)
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
    }

    public ResponseEntity<?> verifyEmail(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = verificationToken.getUser();
        user.setActive(true);
        userRepository.save(user);
        UserRegisterDTO userRegisterDTO = maptoDTO(user);
        return ApiResponse.success(userRegisterDTO, HttpStatus.CREATED.value(), "Verify Success!", null);
    }

}
