package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.config.JwtUtil;
import com.example.courseworkLuchnetskyi.model.User;
import com.example.courseworkLuchnetskyi.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwt;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthDto dto) {
        if (userRepo.findByUsername(dto.username()).isPresent())
            return ResponseEntity.badRequest().body("Username taken");

        userRepo.save(new User(dto.username(), encoder.encode(dto.password())));
        return ResponseEntity.ok("Registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthDto dto,
                                   HttpServletResponse resp) {

        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.username(), dto.password()));

        String token = jwt.generateToken(dto.username());

        resp.setHeader("Set-Cookie",
                "JWT_TOKEN=" + token +
                "; Path=/; Max-Age=" + 7 * 24 * 60 * 60 +
                "; SameSite=None; Secure; HttpOnly");

        return ResponseEntity.ok("Login success");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse resp) {
        resp.setHeader("Set-Cookie",
                "JWT_TOKEN=; Path=/; Max-Age=0; SameSite=None; Secure; HttpOnly");
        return ResponseEntity.ok("Logout success");
    }

    /* ===== DTO ===== */
    public record AuthDto(String username, String password) {}
}
