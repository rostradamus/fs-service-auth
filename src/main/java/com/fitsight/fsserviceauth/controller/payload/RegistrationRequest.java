package com.fitsight.fsserviceauth.controller.payload;

import com.fitsight.fsserviceauth.messageq.envelop.UserMessage;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Data
public class RegistrationRequest {
    @NotBlank
    private String email;

    @NotBlank
    @Size(min = 8, max = 32)
    private String password;

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    public UserMessage toMessage() {
        return UserMessage.builder().email(email).firstName(firstName).lastName(lastName).build();
    }
}
