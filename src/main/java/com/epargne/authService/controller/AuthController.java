package com.epargne.authService.controller;

import com.epargne.authService.Entity.User;
import com.epargne.authService.ErrorHandler.LoginException;
import com.epargne.authService.repository.UserRepository;
import com.epargne.authService.service.AuthService;
import com.epargne.authService.utils.LoginResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Operation(summary = "User login", security = {})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "400", description = "Invalid password or phone number does not exist"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String phoneNumber, @RequestParam String password) {
        try {
            LoginResponse loginResponse = authService.login(phoneNumber, password);
            return ResponseEntity.ok(loginResponse);
        } catch (LoginException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "An unexpected error occurred"));
        }
    }

    @Operation(summary = "Register a new user", security = {})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP sent successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestParam String nom,
            @RequestParam String prenoms,
            @RequestParam String CNI,
            @RequestParam String phoneNumber,
            @RequestParam String password) {
        try {
            // Check if the phone number already exists
            if (userRepository.findByPhoneNumber(phoneNumber) != null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Error: Phone number already exists.");
            }

            // Create a new User object
            User user = new User();
            user.setNom(nom);
            user.setPrenoms(prenoms);
            user.setCNI(CNI);
            user.setPhoneNumber(phoneNumber);
            user.setPassword(password); // Password will be encrypted in the AuthService

            // Register the user using AuthService
            authService.registerUser(user); // Save user
            String otpResponse = authService.sendOtpToUnverifiedNumbers(user); // Send OTP
            return ResponseEntity.ok("Success: " + otpResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error occurred: " + e.getMessage());
        }
    }


    @Operation(summary = "Verify the received OTP")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid OTP"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(@RequestParam String phoneNumber, @RequestParam String otp) {
        try {
            boolean isValid = authService.verifyOtp(phoneNumber, otp); // Verify OTP
            if (isValid) {
                return ResponseEntity.ok("Success: OTP verified successfully.");
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: Invalid OTP.");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error occurred: " + e.getMessage());
        }
    }

    @Operation(summary = "Generate OTP for password reset")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OTP sent successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request - phone number invalid or user not found"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String phoneNumber) {
        try {
            String response = authService.generateOtpForPasswordReset(phoneNumber);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()).toString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "An unexpected error occurred").toString());
        }
    }

    @Operation(summary = "Reset the password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request - passwords do not match or user not found"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            @RequestParam String phoneNumber) { // Keep phoneNumber to identify the user
        try {
            if (!newPassword.equals(confirmPassword)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Error: Passwords do not match.");
            }

            String response = authService.resetPassword(phoneNumber, newPassword);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()).toString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "An unexpected error occurred").toString());
        }
    }

    @PostMapping("/verify-phone")
    public ResponseEntity<?> verifyPhoneNumber(@RequestParam String phoneNumber) {
        User user = userRepository.findByPhoneNumber(phoneNumber);

        Map<String, String> response = new HashMap<>();

        if (user != null) {
            response.put("message", "Phone number found");
            return ResponseEntity.ok(response);
        } else {
            response.put("error", "Phone number not found");
            return ResponseEntity.status(404).body(response);
        }
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody Map<String, String> requestBody) {
        try {
            String phoneNumber = requestBody.get("phoneNumber");
            String response = authService.sendOtpToUnverifiedNumbers(phoneNumber);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error sending OTP: " + e.getMessage());
        }
    }
}
