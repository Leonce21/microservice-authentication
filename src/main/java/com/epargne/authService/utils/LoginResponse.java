package com.epargne.authService.utils;

public class LoginResponse {
    private String message;
    private String token;
    private Integer userId;
    private String userName;
    private String phoneNumber;

    public LoginResponse(String message, String token, Integer userId, String userName, String phoneNumber) {
        this.message = message;
        this.token = token;
        this.userId = userId;
        this.userName = userName;
        this.phoneNumber = phoneNumber;
    }

    // Getters and Setters

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
}
