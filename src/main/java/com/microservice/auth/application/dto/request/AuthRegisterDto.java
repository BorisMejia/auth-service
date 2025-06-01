package com.microservice.auth.application.dto.request;

import jakarta.validation.constraints.*;

public record AuthRegisterDto(

        @NotBlank(message = "The name is required")
        @Size(min = 3, max = 15, message = "The name must be between 3 and 15 characters long")
        String name,
        @Email(message = "The email is incorrect")
        @NotBlank(message = "The email is required")
        String email,
        @NotBlank(message = "The password is required")
        @Size(min = 5, max = 20, message = "The password must be between 5 and 20 characters long")
        String password
) {
}
