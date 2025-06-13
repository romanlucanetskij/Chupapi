package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.model.User;
import com.example.courseworkLuchnetskyi.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.courseworkLuchnetskyi.config.JwtUtil;
import com.example.courseworkLuchnetskyi.model.User;
import com.example.courseworkLuchnetskyi.repository.UserRepository;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> userData) {
        String username = userData.get("username");
        String password = userData.get("password");

        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already taken");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData, HttpServletResponse response) {
        String username = loginData.get("username");
        String password = loginData.get("password");

        System.out.println("Login attempt for username: " + username);

        User user = userRepository.findByUsername(username)
                .orElse(null);

        if (user == null) {
            System.out.println("User not found: " + username);
            return ResponseEntity.status(401).body("Invalid username or password");
        }

        System.out.println("User found: " + user.getUsername() + ", password hash: " + user.getPassword());

        if (!passwordEncoder.matches(password, user.getPassword())) {
            System.out.println("Password does not match for user: " + username);
            return ResponseEntity.status(401).body("Invalid username or password");
        }

        String jwt = jwtUtil.generateToken(user.getUsername());

        System.out.println("Generated JWT token for user: " + username);

        Cookie cookie = new Cookie("JWT_TOKEN", jwt);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); 
        response.addCookie(cookie);

        return ResponseEntity.ok("Login successful");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("JWT_TOKEN", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok("Logout successful");
    }
}
