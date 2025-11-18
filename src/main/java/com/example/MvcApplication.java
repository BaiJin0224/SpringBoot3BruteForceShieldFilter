package com.example;

import com.example.mvc.BruteForceShieldFilter;
import com.example.util.JwtUtil;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

@SpringBootApplication
public class MvcApplication {
    public static void main(String[] args) {
        SpringApplication.run(MvcApplication.class, args);
    }

    @Bean
    public FilterRegistrationBean<BruteForceShieldFilter> bruteForceShieldFilterRegistration() {
        BruteForceShieldFilter filter = new BruteForceShieldFilter();
        filter.setSuspiciousHitThreshold(3)
                .setSuspiciousWindow(Duration.ofDays(1))
                .setNotFoundThreshold(10)
                .setNotFoundWindow(Duration.ofDays(1))
                .setTrustProxy(true);
        filter.addWhitelistIp("8.8.8.8");


        FilterRegistrationBean<BruteForceShieldFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(filter);
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
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
