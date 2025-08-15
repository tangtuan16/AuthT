package com.example.Auth.Services.Jwts;


import com.example.Auth.Models.RefreshToken;
import com.example.Auth.Models.User;
import com.example.Auth.Repositories.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    // Hash refresh token trước khi lưu DB
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Lưu Refresh Token mới
    public RefreshToken saveRefreshToken(User user, String token, String jti,
                                         LocalDateTime issuedAt, LocalDateTime expiresAt,
                                         String deviceInfo, String ip) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(hashToken(token))
                .jti(jti)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .deviceInfo(deviceInfo)
                .ipAddress(ip)
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    // Tìm token hợp lệ
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByTokenHash(hashToken(token));
    }

    // Thu hồi token
    @Transactional
    public void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    // Rotation: thu hồi cũ, cấp mới
    @Transactional
    public RefreshToken rotateToken(RefreshToken oldToken, User user, String newToken, String newJti,
                                    LocalDateTime issuedAt, LocalDateTime expiresAt,
                                    String deviceInfo, String ip) {

        // Đánh dấu token cũ đã bị thay thế
        oldToken.setRevoked(true);
        oldToken.setReplacedBy(newJti);
        refreshTokenRepository.save(oldToken);

        // Lưu token mới
        return saveRefreshToken(user, newToken, newJti, issuedAt, expiresAt, deviceInfo, ip);
    }

    // Revoke toàn bộ token theo user (khi logout tất cả)
    @Transactional
    public void revokeAllTokensByUser(User user) {
        refreshTokenRepository.findAllByUser(user).forEach(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });
    }
}
