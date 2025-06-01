package com.microservice.auth.application.usercase;

import com.microservice.auth.application.service.JwtUtilityService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtUtilityServiceImpl implements JwtUtilityService {

    @Value("classpath:jwtKeys/private_key.pem")
    private Resource privateKeyResource;

    @Value("classpath:jwtKeys/public_key.pem")
    private Resource publicKeyResource;

    @Override
    public Mono<String> generateJWT(UUID id) {
        return loadPrivateKey(privateKeyResource)
                .publishOn(Schedulers.boundedElastic())
                .flatMap(privateKey -> {
                    try {
                        JWSSigner signer = new RSASSASigner(privateKey);
                        Date now = new Date();
                        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                                .subject(id.toString())
                                .issueTime(now)
                                .expirationTime(new Date(now.getTime() + 14400000))
                                .build();

                        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
                        signedJWT.sign(signer);

                        return Mono.just(signedJWT.serialize());
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Error generating JWT", e));
                    }
                });
    }

    @Override
    public Mono<JWTClaimsSet> parseJWT(String jwt) {
        return loadPublicKey(publicKeyResource)
                .publishOn(Schedulers.boundedElastic())
                .flatMap(publicKey -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);

                        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

                        if (!signedJWT.verify(verifier)) {
                            return Mono.error(new JOSEException("Invalid signature"));
                        }

                        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                        if (claimsSet.getExpirationTime().before(new Date())) {
                            return Mono.error(new JOSEException("Expired token"));
                        }

                        return Mono.just(claimsSet);
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Error parsing JWT", e));
                    }
                });
    }

    private Mono<PrivateKey> loadPrivateKey(Resource resource) {
        return Mono.fromCallable(()->{
            byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));

            String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        }).subscribeOn(Schedulers.boundedElastic());

    }

    private Mono<PublicKey> loadPublicKey(Resource resource){
        return Mono.fromCallable(()->{
            byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));

            String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(new PKCS8EncodedKeySpec(decodedKey));
        }).subscribeOn(Schedulers.boundedElastic());

    }
}
