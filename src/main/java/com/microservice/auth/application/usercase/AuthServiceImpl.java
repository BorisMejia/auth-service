package com.microservice.auth.application.usercase;

import com.microservice.auth.application.dto.request.AuthLoginDto;
import com.microservice.auth.application.dto.request.AuthRegisterDto;
import com.microservice.auth.application.dto.response.AuthResponse;
import com.microservice.auth.application.dto.response.RegisterResponseDto;
import com.microservice.auth.application.service.AuthService;
import com.microservice.auth.application.service.JwtUtilityService;
import com.microservice.auth.domain.model.User;
import com.microservice.auth.domain.repository.UserRepository;
import com.microservice.auth.shared.exception.UserAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;

    private final JwtUtilityService jwtUtilityService;

    private final PasswordEncoder passwordEncoder;

    public Mono<AuthResponse> loginUser(AuthLoginDto loginDto){
        return userRepository.findByEmail(loginDto.email())
                .switchIfEmpty(Mono.error(new RuntimeException("User not registered")))
                .flatMap(user -> {
                    if (passwordEncoder.matches(loginDto.password(), user.getPassword())){
                        return jwtUtilityService.generateJWT(user.getId())
                                .map(AuthResponse::new);
                    }else {
                        return Mono.error(new RuntimeException("Authentication failed"));
                    }
                });
    }

    public Mono<RegisterResponseDto> registerUser(AuthRegisterDto registerDto) {
        return userRepository.findByEmail(registerDto.email())
                .flatMap(user -> Mono.<RegisterResponseDto>error(new UserAlreadyExistsException(registerDto.email())))
                .switchIfEmpty(Mono.defer(() -> {
                    User user = new User(
                            null,
                            registerDto.name(),
                            registerDto.email(),
                            passwordEncoder.encode(registerDto.password())
                    );
                    return userRepository.save(user)
                            .thenReturn(new RegisterResponseDto("User successfully registered"));
                }));
    }


}
