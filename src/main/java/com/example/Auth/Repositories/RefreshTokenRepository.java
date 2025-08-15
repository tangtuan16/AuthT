package com.example.Auth.Repositories;

import com.example.Auth.Models.RefreshToken;
import com.example.Auth.Models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    Optional<RefreshToken> findByJti(String jti);

    List<RefreshToken> findAllByUser(User user);

    void deleteByUser(User user);
}
