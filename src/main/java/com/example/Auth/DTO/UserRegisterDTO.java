package com.example.Auth.DTO;

import com.example.Auth.Models.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserRegisterDTO {
    private String username;
    private String password;
    private String email;
    private String roles;

    private UserRegisterDTO maptoDTO(User user) {
        UserRegisterDTO userRegisterDTO = new UserRegisterDTO();
        userRegisterDTO.setUsername(user.getUsername());
        userRegisterDTO.setEmail(user.getEmail());
        userRegisterDTO.setRoles(this.roles);
        return userRegisterDTO;
    }
}
