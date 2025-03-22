package com.epargne.authService.utils;

import java.time.LocalDateTime;

public class OtpUtil {

    private String otp;
    private LocalDateTime expiryTime;

    public OtpUtil(String otp, LocalDateTime expiryTime) {
        this.otp = otp;
        this.expiryTime = expiryTime;
    }

    public String getOtp() {
        return otp;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryTime);
    }
}
