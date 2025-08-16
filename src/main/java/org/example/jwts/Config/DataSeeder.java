package org.example.jwts.Config;

import lombok.RequiredArgsConstructor;
import org.example.jwts.Models.User;
import org.example.jwts.Models.Role;
import org.example.jwts.Repository.RoleRepository;
import org.example.jwts.Repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder encoder;

    @Bean
    CommandLineRunner init() {
        return args -> {
            var rUser = roleRepo.findByName("ROLE_USER")
                    .orElseGet(() -> roleRepo.save(Role.builder().name("ROLE_USER").build()));
            var rAdmin = roleRepo.findByName("ROLE_ADMIN")
                    .orElseGet(() -> roleRepo.save(Role.builder().name("ROLE_ADMIN").build()));

            if (!userRepo.existsByUsername("admin")) {
                var u = User.builder()
                        .username("admin")
                        .email("admin@gmail.com")
                        .password(encoder.encode("admin123"))
                        .roles(Set.of(rUser, rAdmin))
                        .enabled(true)
                        .build();
                userRepo.save(u);
            }
        };
    }
}
