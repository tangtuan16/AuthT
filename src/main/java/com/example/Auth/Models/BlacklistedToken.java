package com.example.Auth.Models;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "blacklisted_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BlacklistedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // jti của AccessToken bị thu hồi
    @Column(nullable = false, unique = true, length = 100)
    private String jti;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(length = 50)
    private String tokenType = "ACCESS";

    @Column(length = 255)
    private String reason;

    @Column(nullable = false)
    private LocalDateTime revokedAt = LocalDateTime.now();

    @Column(nullable = false)
    private LocalDateTime expiresAt;
}
