package com.example.Auth.DTO;

import com.example.Auth.Models.Role;
import com.example.Auth.Models.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserRegisterDTO {
    private String username;
    private String password;
    private String email;
    private String roles;

    public static UserRegisterDTO maptoDTO(User user) {
        UserRegisterDTO dto = new UserRegisterDTO();
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setRoles(user.getRoles().toString());
        return dto;
    }

}
