package com.epargne.authService.ErrorHandler;

public class LoginException extends RuntimeException{
    public LoginException(String message) {
        super(message);
    }
}
