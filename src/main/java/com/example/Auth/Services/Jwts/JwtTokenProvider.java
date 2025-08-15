package com.example.Auth.Services.Jwts;

import com.example.Auth.Models.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access.expiration}")
    private long accessTokenExpirationMs;

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpirationMs;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateAccessToken(User user, String deviceId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(String.valueOf(user.getId()))
                .claim("username", user.getUsername())
                .claim("roles", user.getRoles())
                .claim("type", "access")
                .claim("device_id", deviceId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(accessTokenExpirationMs)))
                .setId(UUID.randomUUID().toString()) // jti
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(User user, String deviceId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(String.valueOf(user.getId()))
                .claim("type", "refresh")
                .claim("device_id", deviceId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(refreshTokenExpirationMs)))
                .setId(UUID.randomUUID().toString()) // jti
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
    }

    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String extractJti(String token) {
        try {
            return parseToken(token).getBody().getId();
        } catch (Exception e) {
            return null;
        }
    }

    public Long extractUserId(String token) {
        try {
            return Long.valueOf(parseToken(token).getBody().getSubject());
        } catch (Exception e) {
            return null;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            Claims claims = parseToken(token).getBody();
            return claims.get("username", String.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String getRolesFromToken(String token) {
        try {
            Claims claims = parseToken(token).getBody();
            return (String) claims.get("roles");
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    public long getExpirationDuration(String token) {
        try {
            Claims claims = parseToken(token).getBody();
            Date expirationDate = claims.getExpiration();
            long now = System.currentTimeMillis();
            long diff = expirationDate.getTime() - now;
            return Math.max(diff, 0);
        } catch (Exception e) {
            return 0; // nếu token không hợp lệ hoặc không có exp
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims claims = parseToken(token).getBody();
            String type = claims.get("type", String.class);
            return "refresh".equalsIgnoreCase(type);
        } catch (Exception e) {
            return false;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String extractDeviceId(String token) {
        try {
            Claims claims = parseToken(token).getBody();
            return (String) claims.get("device_id");
        } catch (Exception e) {
            return e.getMessage();
        }
    }
}
