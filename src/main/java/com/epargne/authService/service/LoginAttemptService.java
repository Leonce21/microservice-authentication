package com.epargne.authService.service;

import com.epargne.authService.Entity.User;
import com.epargne.authService.repository.UserRepository;
import com.epargne.authService.utils.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class LoginAttemptService {
    @Autowired
    private UserRepository userRepository;

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int BLOCK_TIME_MINUTES = 1;

    private final Map<String, Integer> attemptsCache = new HashMap<>();
    private final Map<String, LocalDateTime> blockCache = new HashMap<>();

    public boolean isBlocked(String phoneNumber) {
        LocalDateTime blockTime = blockCache.get(phoneNumber);

        if (blockTime != null) {
            if (blockTime.isAfter(LocalDateTime.now())) {
                return true; // User is still blocked
            } else {
                // Block time expired, remove from cache
                blockCache.remove(phoneNumber);
                attemptsCache.remove(phoneNumber);

                // Unblock user in database
                User user = userRepository.findByPhoneNumber(phoneNumber);
                if (user != null && user.getStatus() == Status.BLOCKED) {
                    user.setStatus(Status.ACTIVE);
                    userRepository.save(user);
                    System.out.println("User automatically unblocked: " + phoneNumber);
                }
            }
        }
        return false;// User is not blocked
    }

    public void loginFailed(String phoneNumber, UserRepository userRepository) {
        if (isBlocked(phoneNumber)) {
            System.out.println("User already blocked: " + phoneNumber);
            return;
        }

        // Increment failed attempt count
        int attempts = attemptsCache.getOrDefault(phoneNumber, 0) + 1;
        attemptsCache.put(phoneNumber, attempts);
        System.out.println("Failed attempts for " + phoneNumber + ": " + attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            System.out.println("Blocking user: " + phoneNumber);
            blockCache.put(phoneNumber, LocalDateTime.now().plusMinutes(1));
            attemptsCache.remove(phoneNumber); // Reset memory cache after blocking

            // Fetch user from DB and update status
            User user = userRepository.findByPhoneNumber(phoneNumber);
            if (user != null) {
                user.setStatus(Status.BLOCKED);
                userRepository.save(user);
                System.out.println("User status updated to BLOCKED in DB: " + phoneNumber);
            }
        }
    }

    public void loginSuccessful(String phoneNumber) {
        attemptsCache.remove(phoneNumber);
        blockCache.remove(phoneNumber);

        // Reset user status to ACTIVE in the database
        User user = userRepository.findByPhoneNumber(phoneNumber);
        if (user != null && user.getStatus() == Status.BLOCKED) {
            user.setStatus(Status.ACTIVE);
            userRepository.save(user);
            System.out.println("User is now ACTIVE: " + phoneNumber);
        }
    }

    @Scheduled(fixedRate = 60000) // Runs every 60 seconds
    public void unblockUsersAutomatically() {
        LocalDateTime now = LocalDateTime.now();
        for (String phoneNumber : blockCache.keySet()) {
            if (blockCache.get(phoneNumber).isBefore(now)) {
                blockCache.remove(phoneNumber);
                attemptsCache.remove(phoneNumber);

                // Unblock user in database
                User user = userRepository.findByPhoneNumber(phoneNumber);
                if (user != null && user.getStatus() == Status.BLOCKED) {
                    user.setStatus(Status.ACTIVE);
                    userRepository.save(user);
                    System.out.println("User automatically unblocked by scheduler: " + phoneNumber);
                }
            }
        }
    }
}
