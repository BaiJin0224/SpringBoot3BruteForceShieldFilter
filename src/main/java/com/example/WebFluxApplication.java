package com.example;

import com.example.util.JwtUtil;
import com.example.webflux.BruteForceShieldWebFluxFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

@SpringBootApplication
public class WebFluxApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebFluxApplication.class, args);
    }

    @Bean
    public BruteForceShieldWebFluxFilter bruteForceShieldWebFilter() {
        return new BruteForceShieldWebFluxFilter()
                .setSuspiciousHitThreshold(0)
                .setSuspiciousWindow(Duration.ofDays(1))
                .setNotFoundThreshold(20)
                .setNotFoundWindow(Duration.ofDays(1))
                .setTrustProxy(true);
    }

    @Bean
    public JwtUtil jwtUtil() {
        return new JwtUtil();
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(factory);
        redisTemplate.setEnableTransactionSupport(true);
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        return redisTemplate;
    }

}
