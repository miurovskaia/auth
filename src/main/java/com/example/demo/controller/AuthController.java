package com.example.demo.controller;

import com.example.demo.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;

    @Autowired
    private Environment env;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        if (env.getProperty("username").equals(request.username) && env.getProperty("password").equals(request.password)) {
            String token = jwtService.generateToken(request.username);
            return ResponseEntity.ok(new JwtResponse(token));
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(@RequestBody ValidationRequest request) {
        if (!jwtService.isServiceRegistered(request.serviceId)) {
            return ResponseEntity.status(403).body(new ValidationResponse(false, "Service not registered"));
        }

        boolean valid = jwtService.validateToken(request.token);
        if (valid) {
            String username = jwtService.extractUsername(request.token);
            System.out.println("username "+username);
            return ResponseEntity.ok(new ValidationResponse(true, username));
        } else {
            return ResponseEntity.ok(new ValidationResponse(false, "Invalid token"));
        }
    }

    public static class LoginRequest {
        public String username;
        public String password;
    }

    public static class JwtResponse {
        public String token;
        public JwtResponse(String token) { this.token = token; }
    }

    public static class ValidationRequest {
        public String token;
        public String serviceId;
    }

    public static class ValidationResponse {
        public boolean valid;
        public String detail;
        public ValidationResponse() {}
        public ValidationResponse(boolean valid, String detail) {
            this.valid = valid;
            this.detail = detail;
        }
    }
}