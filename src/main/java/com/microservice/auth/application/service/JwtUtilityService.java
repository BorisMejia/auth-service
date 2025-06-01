package com.microservice.auth.application.service;

import com.nimbusds.jwt.JWTClaimsSet;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface JwtUtilityService {

    public Mono<String> generateJWT(UUID id);

    public Mono<JWTClaimsSet> parseJWT(String jwt);
}
