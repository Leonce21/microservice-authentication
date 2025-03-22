package com.epargne.authService.service;

import com.epargne.authService.Entity.User;
import com.epargne.authService.repository.UserRepository;
import com.epargne.authService.utils.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String updatePassword(String phoneNumber, String newPassword) {
        User user = userRepository.findByPhoneNumber(phoneNumber);

        if (user == null) {
            throw new RuntimeException("User not found. Please check the phone number.");
        }

        if (user.getStatus() != Status.ACTIVE) {
            throw new RuntimeException("User is not verified. Please verify your account before changing the password.");
        }

        // Encrypt and update the password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return "Password updated successfully.";
    }

    public Integer getCurrentUserId(String phoneNumber) {
        User user = userRepository.findByPhoneNumber(phoneNumber);
        if (user != null) {
            return user.getId();
        } else {
            throw new RuntimeException("User not found.");
        }
    }

    public User findById(Integer userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            return userOptional.get(); // Return the user if found
        } else {
            throw new RuntimeException("User not found with ID: " + userId); // Throw an exception if not found
        }
    }


    public User getUserDetails(String phoneNumber) {
        return userRepository.findByPhoneNumber(phoneNumber);
    }

    // Method to update user details
    public User updateUserDetails(Integer userId, User updatedUser) {
        Optional<User> existingUserOpt = userRepository.findById(userId);
        if (!existingUserOpt.isPresent()) {
            throw new RuntimeException("User not found with ID: " + userId);
        }

        User existingUser = existingUserOpt.get();

        // Updating user fields with new values
        if (updatedUser.getNom() != null) existingUser.setNom(updatedUser.getNom());
        if (updatedUser.getPrenoms() != null) existingUser.setPrenoms(updatedUser.getPrenoms());
        if (updatedUser.getPhoneNumber() != null) existingUser.setPhoneNumber(updatedUser.getPhoneNumber());
        if (updatedUser.getCNI() != null) existingUser.setCNI(updatedUser.getCNI());

        User savedUser = userRepository.save(existingUser);
        System.out.println("Updated User: " + savedUser);
        return savedUser;
    }
}
