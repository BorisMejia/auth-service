package com.microservice.auth.shared.exception;

public class UserAlreadyExistsException extends RuntimeException{

    public UserAlreadyExistsException(String email){
        super("El usuario con el correo '" + email + "' ya se encuentra registrado.");
    }
}
