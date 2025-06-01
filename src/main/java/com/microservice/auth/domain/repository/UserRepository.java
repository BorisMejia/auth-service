package com.microservice.auth.domain.repository;

import com.microservice.auth.domain.model.User;
import reactor.core.publisher.Mono;

public interface UserRepository {

    Mono<User> findByEmail(String email);

    Mono<User> save(User user);

    Mono<Boolean> existsByEmail(String email);
}
