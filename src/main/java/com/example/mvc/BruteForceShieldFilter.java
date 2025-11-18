package com.example.mvc;

import com.example.common.StatusCaptureResponseWrapper;
import com.example.constant.AccountConstant;
import com.example.constant.RedisConstant;
import com.example.util.JwtUtil;
import com.example.util.StringUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
public class BruteForceShieldFilter extends OncePerRequestFilter {

    private RedisTemplate<String, Object> redisTemplate;
    private JwtUtil jwtUtil;

    @Autowired
    public void setRedisTemplate(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Autowired
    public void setJwtUtil(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    // ——可调参数——
    private int suspiciousHitThreshold = 5;
    private Duration suspiciousWindow = Duration.ofHours(1);
    private int notFoundThreshold = 10;
    private Duration notFoundWindow = Duration.ofHours(1);


    private Duration banDuration = Duration.ofMinutes(30);
    private boolean trustProxy = true;
    // 统一白名单：可修改
    private final Set<String> ipWhitelist = java.util.Collections.synchronizedSet(new java.util.HashSet<>());


    @Setter
    private String currentAdminRegisterIp = null;
    private static final long MAX_BAN_DAYS = 64L;


    // 常见探测/撞路径
    private final List<Pattern> suspiciousPathPatterns = List.of(
            Pattern.compile("(?i)^/(cgi-bin|manager|solr|GponForm|v2/_catalog|\\.git|\\.env|wp-|backup|bak|old)(/.*)?$"),
            Pattern.compile("(?i)^/\\.well-known/(security\\.txt|acme-challenge|change-password)$"),
            Pattern.compile("(?i)^/(admin|phpmyadmin|jmx-console|console|login)(/.*)?$"),
            Pattern.compile("(?i)^/(api)?/?(swagger|v2|v3|openapi)(/.*)?$")
    );

    private final List<Pattern> staticResourcePatterns = List.of(
            Pattern.compile("^/(css|js|img|static|favicon\\.ico)(/.*)?$")
    );

    private final List<Pattern> instantBanPathPatterns = List.of(
            Pattern.compile("(?i)^/geoserver/web(/.*)?$"),
            Pattern.compile("(?i)^/cgi-bin/luci//locale(/.*)?$"),
            Pattern.compile("(?i)^/robots\\.txt$"),
            Pattern.compile("(?i)^/security\\.txt$"),
            Pattern.compile("(?i)^/(public|login)?/stylesheets/theme\\.css$"),
            Pattern.compile("(?i)^/index\\.php$"),
            Pattern.compile("(?i)^/(ips|customer|chs)/.*\\.js$"),
            Pattern.compile("(?i)^/hudson(/.*)?$"),
            Pattern.compile("(?i)^/login(/.*)?$"),
            Pattern.compile("(?i)^/sitemap\\.xml$"),
            Pattern.compile("(?i)^/wiki(/.*)?$"),
            Pattern.compile("(?i)^/.+\\.cgi$"),
            Pattern.compile("(?i)^/.+\\.php$"),
            Pattern.compile("(?i)^/download/powershell(/.*)?$")
    );

    @PostConstruct
    public void initWhitelist() {
        ipWhitelist.add("127.0.0.1");
        ipWhitelist.add("::1");
        log.info("Initialized default whitelist IPs: 127.0.0.1, ::1");
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
            throws ServletException, IOException {
        final String ip = clientIp(req);
        final String path = normalizedPath(req);

        if (isStaticResource(normalizedPath(req))) {
            chain.doFilter(req, resp);
            return;
        }

        if (ipWhitelist.contains(ip) || ip.equals(currentAdminRegisterIp)) {
            chain.doFilter(req, resp);
            return;
        }

        String header = req.getHeader(AccountConstant.ACCOUNT_HEADER);
        if (!StringUtil.isEmpty(header)) {
            if (jwtUtil.getId(header) != null) {
                chain.doFilter(req, resp);
                return;
            }
        }


        if (isBanned(ip)) {
            deny(resp, ip, "BLOCKED");
            return;
        }

        if (isInstantBanPath(path)) {
            ban(ip, "instantBanPath");
            log.warn("⚠️ Instant ban triggered! ip={} path={}", ip, path);
            deny(resp, ip, "INSTANT_BAN");
            return;
        }

        if (isSuspiciousPath(path)) {
            long hits = incrWithTtl(counterKey("susp", ip), suspiciousWindow);
            log.debug("Suspicious hit {} from {} -> {}", path, ip, hits);
            if (hits >= suspiciousHitThreshold) {
                ban(ip, "suspiciousPath");
                deny(resp, ip, "SUS_PATH");
                return;
            }
        }

        StatusCaptureResponseWrapper wrapper = new StatusCaptureResponseWrapper(resp);
        try {
            chain.doFilter(req, wrapper);
        } finally {
            int status = wrapper.getStatus();
            if (status == 404 || status == 405 || status == 400) {
                long nf = incrWithTtl(counterKey("nf", ip), notFoundWindow);
                if (nf >= notFoundThreshold) {
                    ban(ip, "tooManyNotFound");
                    log.warn("Banned {} due to excessive {} within window (count={})", ip, status, nf);
                }
            }
        }
    }

    // ——工具方法——
    private String normalizedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return (uri == null || uri.isBlank()) ? "/" : uri;
    }

    private boolean isStaticResource(String path) {
        return staticResourcePatterns.stream().anyMatch(p -> p.matcher(path).matches());
    }

    private boolean isSuspiciousPath(String path) {
        return suspiciousPathPatterns.stream().anyMatch(p -> p.matcher(path).matches());
    }

    private boolean isInstantBanPath(String path) {
        return instantBanPathPatterns.stream().anyMatch(p -> p.matcher(path).matches());
    }

    private boolean isBanned(String ip) {
        return redisTemplate.hasKey(banKey(ip));
    }

    private void ban(String ip, String reason) {
        try {
            String banCountKey = RedisConstant.BRUTE_FORCE_SHIELD + "ban_count:" + ip;
            Long count = redisTemplate.opsForValue().increment(banCountKey);
            long banTimes = (count == null) ? 1L : count;

            long baseSeconds = banDuration.getSeconds();

            double multiplier = Math.pow(2.0, Math.max(0L, banTimes - 1L));
            double computedSecondsDouble = baseSeconds * multiplier;
            long maxSeconds = Duration.ofDays(MAX_BAN_DAYS).getSeconds();

            long finalSeconds;
            if (computedSecondsDouble >= (double) maxSeconds) {
                finalSeconds = maxSeconds;
            } else {
                finalSeconds = Math.max(1L, Math.round(computedSecondsDouble));
            }

            redisTemplate.opsForValue().set(banKey(ip), "banned:" + reason, Duration.ofSeconds(finalSeconds));

            redisTemplate.expire(banCountKey, Duration.ofSeconds(maxSeconds));
            log.info("Banned ip={} reason={} times={} durationSeconds={}", ip, reason, banTimes, finalSeconds);
        } catch (Exception e) {
            log.error("Error while banning ip {}", ip, e);
        }
    }

    private long incrWithTtl(String key, Duration ttl) {
        Long v = null;
        try {
            v = redisTemplate.opsForValue().increment(key);
            if (v != null && v == 1L) {
                redisTemplate.expire(key, ttl);
            }
        } catch (Exception e) {
            log.error("Redis incr error for key={}", key, e);
        }
        return v == null ? 0L : v;
    }

    private String banKey(String ip) {
        return RedisConstant.BRUTE_FORCE_SHIELD + "ban:" + ip;
    }

    private String counterKey(String kind, String ip) {
        return RedisConstant.BRUTE_FORCE_SHIELD + "counter:" + kind + ":" + ip;
    }

    private String clientIp(HttpServletRequest request) {
        if (trustProxy) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                int comma = xff.indexOf(',');
                return comma > 0 ? xff.substring(0, comma).trim() : xff.trim();
            }
            String realIp = request.getHeader("X-Real-IP");
            if (realIp != null && !realIp.isBlank()) return realIp.trim();
            String cf = request.getHeader("CF-Connecting-IP");
            if (cf != null && !cf.isBlank()) return cf.trim();
        }
        return request.getRemoteAddr();
    }

    private void deny(HttpServletResponse resp, String ip, String reason) throws IOException {
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        resp.setContentType("text/plain;charset=UTF-8");
        resp.getWriter().write("Access temporarily blocked. Reason=" + reason + ", ip=" + ip);
    }

    // ——fluent setters（可在配置里微调阈值与窗口）——
    public BruteForceShieldFilter setSuspiciousHitThreshold(int v) {
        this.suspiciousHitThreshold = v;
        return this;
    }

    public BruteForceShieldFilter setNotFoundThreshold(int v) {
        this.notFoundThreshold = v;
        return this;
    }

    public BruteForceShieldFilter setSuspiciousWindow(Duration d) {
        this.suspiciousWindow = d;
        return this;
    }

    public BruteForceShieldFilter setNotFoundWindow(Duration d) {
        this.notFoundWindow = d;
        return this;
    }

    public BruteForceShieldFilter setBanDuration(Duration d) {
        this.banDuration = d;
        return this;
    }

    public BruteForceShieldFilter setTrustProxy(boolean v) {
        this.trustProxy = v;
        return this;
    }

    public void clearCurrentAdminRegisterIp() {
        this.currentAdminRegisterIp = null;
    }

    /**
     * 添加动态 IP 白名单
     */
    public void addWhitelistIp(String ip) {
        if (ip != null && !ip.isBlank()) {
            ipWhitelist.add(ip.trim());
            log.info("Added IP to whitelist: {}", ip);
        }
    }


}
