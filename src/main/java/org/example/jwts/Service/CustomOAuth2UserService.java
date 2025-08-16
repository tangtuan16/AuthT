package org.example.jwts.Service;

import org.example.jwts.Models.Role;
import org.example.jwts.Models.User;
import org.example.jwts.Repository.RoleRepository;
import org.example.jwts.Repository.UserRepository;
import org.example.jwts.Service.JwtService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class CustomOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // Gọi OidcUserService mặc định để lấy thông tin user từ Google
        OidcUserService delegate = new OidcUserService();
        OidcUser oidcUser = delegate.loadUser(userRequest);

        // Lấy attributes từ OIDC
        Map<String, Object> attributes = oidcUser.getAttributes();
        System.out.println("OIDC attributes: " + attributes);

        String email = oidcUser.getEmail();
        String name = (String) attributes.get("name");
        String googleId = oidcUser.getSubject();

        if (email == null) {
            throw new RuntimeException("Email not found from Google OIDC");
        }

        // Lấy role mặc định
        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        // Tìm user hoặc tạo mới
        User user = userRepository.findByEmail(email)
                .map(existingUser -> {
                    existingUser.setName(name);
                    existingUser.setGoogleID(googleId);
                    return existingUser;
                })
                .orElseGet(() -> User.builder()
                        .name(name)
                        .email(email)
                        .googleID(googleId)
                        .roles(Set.of(defaultRole))
                        .build()
                );

        userRepository.save(user);

        // Sinh JWT token
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password("")
                .authorities(user.getRoles().stream().map(Role::getName).toArray(String[]::new))
                .build();

        String accessToken = jwtService.generateAccessToken(userDetails, new HashMap<>());
        String refresh = jwtService.generateRefreshToken(userDetails);

        Map<String, Object> newAttributes = new HashMap<>(attributes);
        newAttributes.put("accessToken", accessToken);
        newAttributes.put("refreshToken", refresh);
        return new DefaultOidcUser(
                userDetails.getAuthorities(),
                oidcUser.getIdToken(),
                new OidcUserInfo(newAttributes),
                "email"
        );
    }
}
