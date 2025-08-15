package com.example.Auth.Controllers;

import com.example.Auth.DTO.LoginRequest;
import com.example.Auth.DTO.RegisterRequest;
import com.example.Auth.DTO.UserRegisterDTO;
import com.example.Auth.Services.AuthService;
import com.example.Auth.Utils.ApiResponse;
import com.example.Auth.Utils.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private final AuthService authService;

    private final Log log = (Log) LogFactory.getLog(AuthController.class);

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtils.generateToken(userDetails);
        Map<String, String> tokenData = new HashMap<>();
        tokenData.put("token", token);
        return ApiResponse.success(tokenData, HttpStatus.OK.value(), "success", null);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        UserRegisterDTO userRegisterDTO = authService.register(registerRequest);
        log.error("register: " + userRegisterDTO.getUsername());
        return ApiResponse.success(userRegisterDTO, HttpStatus.CREATED.value(), "Succses", null);
    }

}
