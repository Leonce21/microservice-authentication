package com.epargne.authService.controller;

import com.epargne.authService.Entity.User;
import com.epargne.authService.dto.ResetPasswordRequest;
import com.epargne.authService.service.UserService;
import com.epargne.authService.utils.JwtUtil;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        String phoneNumber = request.getPhoneNumber();
        String newPassword = request.getNewPassword();
        String confirmNewPassword = request.getConfirmNewPassword();

        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: Numéro de téléphone requis.");
        }

        if (newPassword == null || confirmNewPassword == null || !newPassword.equals(confirmNewPassword)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: Les mots de passe ne correspondent pas.");
        }

        try {
            String message = userService.updatePassword(phoneNumber, newPassword);
            return ResponseEntity.ok(message);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }


    //    Updates the user's password based on their phone number
    @Operation(summary = "Update user password", security = {@SecurityRequirement(name = "bearerAuth")})
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password updated successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request - user not found or invalid data"),
            @ApiResponse(responseCode = "403", description = "Forbidden - user not verified, token expired, or token not provided"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestParam String newPassword, @RequestParam String confirmNewPassword) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Ensure the user is authenticated
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error: Token is required or invalid.");
        }

        // Extract phone number from the authentication
        String phoneNumber = authentication.getName();
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error: Invalid token. Phone number is missing.");
        }

        // Check if passwords match
        if (newPassword == null || confirmNewPassword == null || !newPassword.equals(confirmNewPassword)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: Passwords do not match.");
        }

        try {
            String message = userService.updatePassword(phoneNumber, newPassword);
            return ResponseEntity.ok(message);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }


    @Operation(summary = "Get current user ID", security = {@SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/current-id")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Integer> getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Ensure the user is authenticated
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        // Extract phone number from the authentication
        String phoneNumber = authentication.getName();
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        }

        try {
            Integer userId = userService.getCurrentUserId(phoneNumber);
            return ResponseEntity.ok(userId);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    @Operation(summary = "Get user details", security = {@SecurityRequirement(name = "bearerAuth")})
    @GetMapping("/details")
    public ResponseEntity<?> getUserDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error: Unauthorized access.");
        }

        String phoneNumber = authentication.getName();
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: Invalid token.");
        }

        User user = userService.getUserDetails(phoneNumber);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Error: User not found.");
        }

        return ResponseEntity.ok(user);
    }

    @ApiOperation(value = "Update user details", notes = "Update an existing user's details by their ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User updated successfully"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "400", description = "Invalid request")
    })
    @SecurityRequirement(name = "bearerAuth")
    @PutMapping("/update/{userId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<User> updateUserDetails(
            @PathVariable Integer userId,
            @RequestBody User updatedUser) {
        try {
            // This checks if the user with the given ID exists
            User existingUser = userService.findById(userId);
            if (existingUser == null) {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
            User updated = userService.updateUserDetails(userId, updatedUser);
            return new ResponseEntity<>(updated, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
