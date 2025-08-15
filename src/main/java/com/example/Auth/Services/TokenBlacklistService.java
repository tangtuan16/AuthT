package com.example.Auth.Services;

import com.example.Auth.Services.Jwts.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtTokenProvider tokenProvider;
    private static final String BLACKLIST_PREFIX = "blacklist:";

    public void blacklistToken(Long userId, String deviceId, String type, String token, long expirationMillis) {
        redisTemplate.opsForValue().set(
                BLACKLIST_PREFIX + type + ":" + userId + ":" + deviceId ,
                token,
                expirationMillis,
                TimeUnit.MILLISECONDS
        );
    }

    public boolean isBlacklisted(Long userId, String deviceId, String type, String token) {
        String key = BLACKLIST_PREFIX + type + ":" + userId + ":" + deviceId;
        Object storedToken = redisTemplate.opsForValue().get(key);

        // Nếu có token trong blacklist và khớp -> true
        if (storedToken != null && storedToken.equals(token)) {
            log.info("Token IS blacklisted -> key={}", key);
            return true;
        }

        log.info("Token NOT blacklisted -> key={}", key);
        return false;
    }
}
