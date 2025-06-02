package com.microservice.auth.application.service;

import com.microservice.auth.application.dto.request.AuthLoginDto;
import com.microservice.auth.application.dto.request.AuthRegisterDto;
import com.microservice.auth.application.dto.response.AuthResponse;
import com.microservice.auth.application.dto.response.RegisterResponseDto;
import reactor.core.publisher.Mono;

public interface AuthService {

    public Mono<AuthResponse> loginUser(AuthLoginDto loginDto);
    public Mono<RegisterResponseDto> registerUser(AuthRegisterDto registerDto);

}
