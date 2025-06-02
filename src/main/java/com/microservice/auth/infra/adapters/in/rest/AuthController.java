package com.microservice.auth.infra.adapters.in.rest;

import com.microservice.auth.application.dto.request.AuthLoginDto;
import com.microservice.auth.application.dto.request.AuthRegisterDto;
import com.microservice.auth.application.dto.response.AuthResponse;
import com.microservice.auth.application.dto.response.RegisterResponseDto;
import com.microservice.auth.application.service.AuthService;
import com.microservice.auth.shared.exception.UserAlreadyExistsException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@Valid @RequestBody AuthLoginDto loginDto) {
        return authService.loginUser(loginDto)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthResponse("Error: " + e.getMessage()))));
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<RegisterResponseDto>> register(@Valid @RequestBody AuthRegisterDto registerDto) {
        return authService.registerUser(registerDto)
                .map(ResponseEntity::ok)
                .onErrorResume(UserAlreadyExistsException.class,
                        ex -> Mono.just(ResponseEntity
                                .status(HttpStatus.CONFLICT)
                                .body(new RegisterResponseDto(ex.getMessage())))
                );
    }

}
