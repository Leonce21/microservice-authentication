package com.epargne.authService.service;

import com.epargne.authService.ErrorHandler.LoginException;
import com.epargne.authService.utils.OtpUtil;
import com.epargne.authService.Entity.User;
import com.epargne.authService.repository.UserRepository;
import com.epargne.authService.utils.JwtUtil;
import com.epargne.authService.utils.LoginResponse;
import com.epargne.authService.utils.Status;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private LoginAttemptService loginAttemptService;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final Map<String, OtpUtil> otpStore = new HashMap<>(); // Store OTPs temporarily

    @Value("${twilio.account_sid}")
    private String accountSid;

    @Value("${twilio.auth_token}")
    private String authToken;

    @Value("${twilio.phone_number}")
    private String twilioPhoneNumber;

    @PostConstruct
    public void init() {
        // Initialize Twilio
        Twilio.init(accountSid, authToken);
    }

    public LoginResponse login(String phoneNumber, String password) throws LoginException {
        User user = userRepository.findByPhoneNumber(phoneNumber);

        if (user == null) {
            throw new RuntimeException("Phone number does not exist.");
        }

        // Check if the user is BLOCKED (from DB, not just memory)
        if (user.getStatus() == Status.BLOCKED) {
            throw new LoginException("Your account is blocked for 1 minutes. Please try again later.");
        }

        // Check password validity
        if (!passwordEncoder.matches(password, user.getPassword())) {
            loginAttemptService.loginFailed(phoneNumber, userRepository);

            // Check if user is now blocked
            if (loginAttemptService.isBlocked(phoneNumber)) {
                user.setStatus(Status.BLOCKED);
                userRepository.save(user);
                throw new LoginException("Your account is now blocked for 1 minutes due to multiple failed attempts.");
            }

            throw new LoginException("Invalid password. Please try again.");
        }

        // Successful login
        loginAttemptService.loginSuccessful(phoneNumber);
        user.setStatus(Status.ACTIVE); // Reset status on successful login
        userRepository.save(user);

        // Generate JWT token
        String token = jwtUtil.generateToken(phoneNumber);

        // Return user details along with the token and success message
        return new LoginResponse("You have successfully logged in", token, user.getId(), user.getNom(), user.getPhoneNumber());
    }

    // Method to register user
    public User registerUser(User user) {
        // Save user
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    // Method to generate OTP
    private String generateOtp() {
        // Simple OTP generation logic
        return String.format("%06d", new Random().nextInt(1000000));
    }

    // Method to send OTP
    private void sendOtpViaTwilio(String phoneNumber, String otp) {
        String messageBody = "Your OTP is: " + otp + ". Do not share it with anyone.";
        try {
            Message message = Message.creator(
                    new PhoneNumber(phoneNumber),
                    new PhoneNumber(twilioPhoneNumber),
                    messageBody
            ).create();
            System.out.println("OTP sent successfully to " + phoneNumber + ": " + message.getSid());
        } catch (Exception e) {
            System.err.println("Failed to send OTP to " + phoneNumber + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    public String sendOtpToUnverifiedNumbers(User user) {
        String phoneNumber = user.getPhoneNumber();
        String otp = generateOtp();
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(1);
        otpStore.put(phoneNumber, new OtpUtil(otp, expiryTime));
        sendOtpViaTwilio(phoneNumber, otp);
        return "OTP sent to " + phoneNumber;
    }

    // New method to send OTP based on phone number
    public String sendOtpToUnverifiedNumbers(String phoneNumber) {
        // Check if the phone number exists
        User user = userRepository.findByPhoneNumber(phoneNumber);

        if (user == null) {
            throw new RuntimeException("Phone number not found");
        }

        // Generate OTP (using utility method)
        String otp = generateOtp();

        // Store OTP securely (this can be done in DB or cache)
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(1);
        otpStore.put(phoneNumber, new OtpUtil(otp, expiryTime));

        // Send OTP via SMS or another method
        sendOtpViaTwilio(phoneNumber, otp);
        return "OTP sent to " + phoneNumber;
    }

//    public String registerUserWithOtp(User user) {
//        String otp = generateOtp(); // Generate OTP
//        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(1); // Set expiry time
//        otpStore.put(user.getPhoneNumber(), new OtpUtil(otp, expiryTime)); // Store OTP with expiry
//        sendOtp(user.getPhoneNumber(), otp); // Send OTP
//        return "OTP sent to " + user.getPhoneNumber();
//    }

    public boolean verifyOtp(String phoneNumber, String otp) {
        OtpUtil otpEntry = otpStore.get(phoneNumber); // Retrieve OTP entry
        if (otpEntry == null || otpEntry.isExpired()) {
            return false; // OTP not found or expired
        }
        if (otpEntry.getOtp().equals(otp)) {
            User user = userRepository.findByPhoneNumber(phoneNumber);
            if (user != null) {
                user.setStatus(Status.ACTIVE); // Update status to ACTIVE after OTP verification
                userRepository.save(user);
            }
            otpStore.remove(phoneNumber);
            return true;
        }
        return false; // Check validity
    }

    public String generateOtpForPasswordReset(String phoneNumber) {
        User user = userRepository.findByPhoneNumber(phoneNumber);
        if (user == null) {
            throw new RuntimeException("User not found with this phone number.");
        }

        return sendOtpToUnverifiedNumbers(user); // Reuse the OTP sending logic
    }

    public String resetPassword(String phoneNumber, String newPassword) {
        User user = userRepository.findByPhoneNumber(phoneNumber);
        if (user == null) {
            throw new RuntimeException("User not found.");
        }

        user.setPassword(passwordEncoder.encode(newPassword)); // Encrypt the new password
        userRepository.save(user); // Save the updated user

        return "Password reset successfully.";
    }


}
