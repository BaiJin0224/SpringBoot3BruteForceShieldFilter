package com.example.util;

import com.example.constant.AccountConstant;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@ConfigurationProperties("com.example.jwt")
@Data
@Slf4j
public class JwtUtil {
    private String key;
    private long ttl;
    private Key signingKey;
    private JwtParser jwtParser;

    @PostConstruct
    public void init() {
        log.info("JWTUtil init with key: {}   ttl: {}", key, ttl);
        signingKey = new SecretKeySpec(key.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        jwtParser = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build();
    }

    public String createJwt(Map<String, Object> claims) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        JwtBuilder builder = Jwts.builder()
                .setIssuedAt(now)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .setClaims(claims);
        if (ttl > 0) {
            builder.setExpiration(new Date(nowMillis + ttl));
        }
        return builder.compact();
    }

    public Claims parseJWT(String jwtStr) {
        if (jwtStr == null || jwtStr.isBlank()) {
            log.warn("JWT string is null or blank.");
            return null;
        }

        try {
            return jwtParser.parseClaimsJws(jwtStr).getBody();
        } catch (Exception ignore) {
            return null;
        }
    }


    public Long getId(String token) {
        return Long.parseLong(parseJWT(token).get(AccountConstant.TOKEN_ID, String.class));
    }
}
