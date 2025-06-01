package com.microservice.auth.application.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record AuthLoginDto(

        @Email
        String email,
        @NotBlank
        String password
) {
}
