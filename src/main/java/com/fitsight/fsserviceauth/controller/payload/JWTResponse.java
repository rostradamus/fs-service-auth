package com.fitsight.fsserviceauth.controller.payload;

import com.fitsight.fsserviceauth.model.User;
import lombok.Data;

import java.util.List;

@Data
public class JWTResponse {
    private String token;
    private String type = "Bearer";
    private String id;
    private String email;
    private User user;
    private List<String> roles;

    public JWTResponse(String token, String id, String email, List<String> roles, User user) {
        this.token = token;
        this.id = id;
        this.email = email;
        this.roles = roles;
        this.user = user;
    }
}

