package com.microservice.auth.infra.adapters.out.db.mapper;

import com.microservice.auth.domain.model.User;
import com.microservice.auth.infra.adapters.out.db.entity.UserEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserEntity toEntity(User user);
    User toModel(UserEntity entity);
}
