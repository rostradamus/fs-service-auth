package com.fitsight.fsserviceauth.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.Date;
import java.util.UUID;

@Document
@Data
public class RefreshToken {
    @Id
    private String id;

    private String username;

    @Indexed(expireAfterSeconds = 86400)
    Date createdAt;

    public RefreshToken(String username) {
        this.id = UUID.randomUUID().toString();
        this.username = username;
        this.createdAt = new Date();
    }
}
