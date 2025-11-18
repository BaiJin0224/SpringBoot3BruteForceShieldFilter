package com.example.webflux;

import com.example.constant.AccountConstant;
import com.example.constant.RedisConstant;
import com.example.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BruteForceShieldWebFluxFilter implements WebFilter {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private JwtUtil jwtUtil;

    private int suspiciousHitThreshold = 5;
    private Duration suspiciousWindow = Duration.ofHours(1);
    private int notFoundThreshold = 10;
    private Duration notFoundWindow = Duration.ofHours(1);

    private Duration banDuration = Duration.ofMinutes(30);
    private boolean trustProxy = true;

    private final Set<String> ipWhitelist =
            java.util.Collections.synchronizedSet(new java.util.HashSet<>());


    @Setter
    private String currentAdminRegisterIp = null;

    private static final long MAX_BAN_DAYS = 64L;

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
        log.info("Initialized default IP whitelist");
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String ip = clientIp(exchange);
        String path = normalizedPath(exchange);

        // --- static resource ---
        if (isStaticResource(path)) {
            return chain.filter(exchange);
        }

        // --- IP 白名单 ---
        if (ipWhitelist.contains(ip) || ip.equals(currentAdminRegisterIp)) {
            return chain.filter(exchange);
        }

        // --- 登录状态豁免 ---
        String header = exchange.getRequest().getHeaders().getFirst(AccountConstant.ACCOUNT_HEADER);
        if (StringUtils.hasText(header)) {
            if (jwtUtil.getId(header) != null) {
                return chain.filter(exchange);
            }
        }

        // --- 已封禁 ---
        if (isBanned(ip)) {
            return deny(exchange, ip, "BLOCKED");
        }

        // --- instant ban ---
        if (isInstantBanPath(path)) {
            ban(ip, "instantBanPath");
            log.warn("⚠️ Instant ban triggered! ip={} path={}", ip, path);
            return deny(exchange, ip, "INSTANT_BAN");
        }

        // --- suspicious path ---
        if (isSuspiciousPath(path)) {
            long hits = incrWithTtl(counterKey("susp", ip), suspiciousWindow);
            log.debug("Suspicious hit {} from {} -> {}", path, ip, hits);
            if (hits >= suspiciousHitThreshold) {
                ban(ip, "suspiciousPath");
                return deny(exchange, ip, "SUS_PATH");
            }
        }

        // ---- 捕获响应状态，不使用 Servlet Wrapper ----
        exchange.getResponse().beforeCommit(() -> {
            HttpStatusCode status = exchange.getResponse().getStatusCode();
            if (status != null && (status.value() == 404 || status.value() == 405 || status.value() == 400)) {
                long nf = incrWithTtl(counterKey("nf", ip), notFoundWindow);
                if (nf >= notFoundThreshold) {
                    ban(ip, "tooManyNotFound");
                    log.warn("Banned {} due to excessive {} within window (count={})", ip, status, nf);
                }
            }
            return Mono.empty();
        });

        return chain.filter(exchange);
    }

    // ---- WebFlux 版路径与 IP 工具方法 ----

    private String normalizedPath(ServerWebExchange exchange) {
        String uri = exchange.getRequest().getURI().getPath();
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

    private String clientIp(ServerWebExchange exchange) {
        if (trustProxy) {
            String xff = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
            if (StringUtils.hasText(xff)) {
                int comma = xff.indexOf(',');
                return comma > 0 ? xff.substring(0, comma).trim() : xff.trim();
            }
            String real = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
            if (StringUtils.hasText(real)) return real;
            String cf = exchange.getRequest().getHeaders().getFirst("CF-Connecting-IP");
            if (StringUtils.hasText(cf)) return cf;
        }
        return Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
    }

    private Mono<Void> deny(ServerWebExchange exchange, String ip, String reason) {
        ServerHttpResponse resp = exchange.getResponse();
        resp.setStatusCode(HttpStatus.FORBIDDEN);
        byte[] bytes = ("Access temporarily blocked. Reason=" + reason + ", ip=" + ip)
                .getBytes();
        return resp.writeWith(Mono.just(resp.bufferFactory().wrap(bytes)));
    }

    // ---- Redis 辅助方法（与你原来的逻辑一致） ----

    private void ban(String ip, String reason) {
        try {
            String banCountKey = RedisConstant.BRUTE_FORCE_SHIELD + "ban_count:" + ip;
            Long count = redisTemplate.opsForValue().increment(banCountKey);
            long banTimes = (count == null) ? 1L : count;

            long baseSeconds = banDuration.getSeconds();

            double multiplier = Math.pow(2.0, Math.max(0L, banTimes - 1L));
            double computed = baseSeconds * multiplier;
            long maxSeconds = Duration.ofDays(MAX_BAN_DAYS).getSeconds();

            long finalSeconds = computed >= maxSeconds ?
                    maxSeconds : Math.max(1L, Math.round(computed));

            redisTemplate.opsForValue()
                    .set(banKey(ip), "banned:" + reason, Duration.ofSeconds(finalSeconds));

            redisTemplate.expire(banCountKey, Duration.ofSeconds(maxSeconds));

            log.info("Banned ip={} reason={} times={} durationSeconds={}", ip, reason, banTimes, finalSeconds);
        } catch (Exception e) {
            log.error("Error while banning ip {}", ip, e);
        }
    }

    private long incrWithTtl(String key, Duration ttl) {
        try {
            Long v = redisTemplate.opsForValue().increment(key);
            if (v != null && v == 1L) {
                redisTemplate.expire(key, ttl);
            }
            return v == null ? 0L : v;
        } catch (Exception e) {
            log.error("Redis incr error for key={}", key, e);
            return 0;
        }
    }

    private String banKey(String ip) {
        return RedisConstant.BRUTE_FORCE_SHIELD + "ban:" + ip;
    }

    private String counterKey(String kind, String ip) {
        return RedisConstant.BRUTE_FORCE_SHIELD + "counter:" + kind + ":" + ip;
    }

    // ---- Fluent Setters（保留原来的 API） ----

    public BruteForceShieldWebFluxFilter setSuspiciousHitThreshold(int v) {
        this.suspiciousHitThreshold = v;
        return this;
    }

    public BruteForceShieldWebFluxFilter setNotFoundThreshold(int v) {
        this.notFoundThreshold = v;
        return this;
    }

    public BruteForceShieldWebFluxFilter setSuspiciousWindow(Duration d) {
        this.suspiciousWindow = d;
        return this;
    }

    public BruteForceShieldWebFluxFilter setNotFoundWindow(Duration d) {
        this.notFoundWindow = d;
        return this;
    }

    public BruteForceShieldWebFluxFilter setBanDuration(Duration d) {
        this.banDuration = d;
        return this;
    }

    public BruteForceShieldWebFluxFilter setTrustProxy(boolean v) {
        this.trustProxy = v;
        return this;
    }

    public void clearCurrentAdminRegisterIp() {
        this.currentAdminRegisterIp = null;
    }

    public void addWhitelistIp(String ip) {
        if (ip != null && !ip.isBlank()) {
            ipWhitelist.add(ip.trim());
            log.info("Added IP to whitelist: {}", ip);
        }
    }

}
