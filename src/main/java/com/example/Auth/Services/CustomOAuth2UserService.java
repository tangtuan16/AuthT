package com.example.Auth.Services;

import com.example.Auth.Models.Role;
import com.example.Auth.Models.User;
import com.example.Auth.Repositories.RoleRepository;
import com.example.Auth.Repositories.UserRepository;
import com.example.Auth.Services.Jwts.JwtTokenProvider;
import com.example.Auth.Services.Jwts.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional
public class CustomOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final HttpServletRequest request;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUserService delegate = new OidcUserService();
        OidcUser oidcUser = delegate.loadUser(userRequest);

        Map<String, Object> attributes = oidcUser.getAttributes();
        String email = oidcUser.getEmail();
        String name = (String) attributes.get("name");
        String googleId = oidcUser.getSubject();

        if (email == null) {
            throw new RuntimeException("Email not found from Google OIDC");
        }

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        User user = userRepository.findByEmail(email)
                .map(existing -> {
                    existing.setName(name);
                    existing.setGoogleID(googleId);
                    if (existing.getRoles() == null || existing.getRoles().isEmpty()) {
                        existing.setRoles(Set.of(defaultRole));
                    }
                    return existing;
                })
                .orElseGet(() -> {
                    User u = new User();
                    u.setName(name);
                    u.setEmail(email);
                    u.setGoogleID(googleId);
                    u.setRoles(Set.of(defaultRole));
                    return u;
                });
        userRepository.save(user);

        // Sinh token từ User (KHÔNG dùng UserDetails)
        String deviceId = Optional.ofNullable(request.getHeader("User-Agent"))
                .map(h -> h.replaceAll("\\s+", "_"))
                .orElse("oauth2_default");
        String accessToken = jwtTokenProvider.generateAccessToken(user, deviceId);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user, deviceId);

        // Quản lý refresh token stateful, lưu xuống DB
        Map<String, Object> newAttributes = new HashMap<>(attributes);
        newAttributes.put("access_token", accessToken);
        newAttributes.put("refresh_token", refreshToken);

        // Build DefaultOidcUser (truyền authorities từ user.roles)
        List<String> roleNames = user.getRoles().stream().map(Role::getName).toList();
        var authorities = roleNames.stream()
                .map(org.springframework.security.core.authority.SimpleGrantedAuthority::new)
                .toList();

        return new DefaultOidcUser(
                authorities,
                oidcUser.getIdToken(),
                new OidcUserInfo(newAttributes),
                "email"
        );
    }
}
