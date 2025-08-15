package com.example.Auth.Models;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Mỗi token thuộc về 1 user
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // Hash của Refresh Token (không lưu token thật)
    @Column(nullable = false, unique = true, length = 255)
    private String tokenHash;

    // jti - JWT ID của Refresh Token
    @Column(nullable = false, unique = true, length = 100)
    private String jti;

    @Column(nullable = false)
    private LocalDateTime issuedAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private Boolean revoked = false;

    // jti của token mới (dùng khi rotation)
    @Column(length = 100)
    private String replacedBy;

    // Thông tin thiết bị & IP
    @Column(length = 255)
    private String deviceInfo;

    @Column(length = 45)
    private String ipAddress;

    @Column
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column
    private LocalDateTime updatedAt = LocalDateTime.now();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}

