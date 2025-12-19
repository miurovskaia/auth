package com.example.demo.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Service
public class JwtService {

   @Autowired
   private Environment env;

    public boolean isServiceRegistered(String serviceId) {
        String serviceList = env.getProperty("registeredServices");
        String[] parts = serviceList.split(",");
        Set<String> serviceSet = new HashSet<>(Arrays.asList(parts));
        return serviceSet.contains(serviceId);
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(env.getProperty("jwtExpiration"))))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        Claims claims = parseToken(token).getPayload();
        return claims.getSubject();
    }

    private Jws<Claims> parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token);
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = env.getProperty("jwtSecret").getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
}