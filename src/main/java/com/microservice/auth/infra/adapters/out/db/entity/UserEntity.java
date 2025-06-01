package com.microservice.auth.infra.adapters.out.db.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Table("users")
public class UserEntity {

    @Id
    private UUID id;
    private String name;
    private String email;
    private String password;
}
