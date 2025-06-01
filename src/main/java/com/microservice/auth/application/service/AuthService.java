package com.microservice.auth.application.service;

import com.microservice.auth.application.dto.request.AuthLoginDto;
import com.microservice.auth.application.dto.request.AuthRegisterDto;
import com.microservice.auth.application.dto.response.AuthResponse;
import reactor.core.publisher.Mono;

public interface AuthService {

    public Mono<AuthResponse> loginUser(AuthLoginDto loginDto);
    public Mono<Object> registerUser(AuthRegisterDto registerDto);

}
