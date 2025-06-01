package com.microservice.auth.infra.adapters.out.db.adapter;

import com.microservice.auth.domain.model.User;
import com.microservice.auth.domain.repository.UserRepository;
import com.microservice.auth.infra.adapters.out.db.mapper.UserMapper;
import com.microservice.auth.infra.adapters.out.db.repository.UserRepositoryPostgres;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Repository
public class UserRepositoryImpl implements UserRepository {
    private final UserRepositoryPostgres repositoryPostgres;
    private final UserMapper userMapper;
    @Override
    public Mono<User> findByEmail(String email) {
        return repositoryPostgres.findByEmail(email)
                .map(userMapper::toModel);
    }

    @Override
    public Mono<User> save(User user) {
        return repositoryPostgres.save(userMapper.toEntity(user))
                .map(userMapper::toModel);
    }

    @Override
    public Mono<Boolean> existsByEmail(String email) {
        return repositoryPostgres.existsByEmail(email);
    }
}
