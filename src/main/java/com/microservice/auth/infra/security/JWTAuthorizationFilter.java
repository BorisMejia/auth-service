package com.microservice.auth.infra.security;

import com.microservice.auth.application.service.JwtUtilityService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

@RequiredArgsConstructor
public class JWTAuthorizationFilter implements WebFilter {

    JwtUtilityService jwtUtilityService;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (header == null  || !header.startsWith("Bearer ")){
            return chain.filter(exchange);
        }

        String token = header.substring(7);

        return jwtUtilityService.parseJWT(token)
                .flatMap(claims -> {
                    Authentication auth = new UsernamePasswordAuthenticationToken(
                            claims.getSubject(), null, Collections.emptyList()
                    );
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
}
