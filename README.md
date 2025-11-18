# SpringBoot3 Brute Force Shield Filter

基于 Spring Boot 3 的教学级暴力扫描防御插件示例，提供 Servlet（Spring MVC）与 WebFlux 双版本过滤器。通过 Redis 记录请求行为，对恶意扫描、异常路径或频繁 404 的来源 IP 进行限速、递增封禁，保护示例项目不被撞库、目录遍历或敏感接口探测。

## 功能特点
- **双运行时适配**：同时提供 `BruteForceShieldFilter`（MVC）与 `BruteForceShieldWebFluxFilter`（WebFlux）两种实现，满足不同 Web 栈。
- **基于 Redis 的计数与封禁**：按 IP 记录可疑访问、404/405/400 频率以及封禁次数，支持在容器或多实例间共享状态。
- **多种可疑信号**：
  - 常见扫描路径（`/.git`、`/admin`、`/swagger` 等）累积达到阈值后封禁。
  - 部分高危路径（`.php`、`.cgi`、`/geoserver/web` 等）直接触发即时封禁。
  - 频繁 404/405/400 返回码被视为探测，超过阈值即封禁。
- **指数回退封禁时长**：每次被封禁后时长翻倍，上限 64 天，避免反复试探。
- **白名单与登录豁免**：支持静态/动态 IP 白名单；持有 JWT（默认请求头 `your_app_account`）的登录用户直接放行。
- **可调阈值**：通过流式 setter 微调可疑路径阈值、404 阈值、统计窗口及是否信任代理头。

## 运行要求
- JDK 17+
- Maven 3.x
- 可用的 Redis 实例（用于计数与封禁状态存储）

## 快速开始（示例工程）
1. **配置 Redis 与 JWT**：在 `application.yml` 中准备连接信息及示例 JWT 配置：
   ```yaml
   spring:
     data:
       redis:
         host: localhost
         port: 6379
   com:
     example:
       jwt:
         key: my-demo-signing-key
         ttl: 3600000   # 毫秒
   ```
2. **选择运行模式**：
   - 传统 Servlet 应用：运行 `MvcApplication`，自动注册 `BruteForceShieldFilter` 到 `/*` 路径。【F:src/main/java/com/example/MvcApplication.java†L20-L38】
   - 响应式 WebFlux 应用：运行 `WebFluxApplication`，自动注册 `BruteForceShieldWebFluxFilter`。【F:src/main/java/com/example/WebFluxApplication.java†L17-L33】
3. **启动项目**：
   ```bash
   mvn spring-boot:run -Dspring-boot.run.main-class=com.example.MvcApplication
   # 或
   mvn spring-boot:run -Dspring-boot.run.main-class=com.example.WebFluxApplication
   ```
4. **验证效果**：
   - 正常请求应直接返回业务响应。
   - 访问高危路径（如 `/index.php`）应收到 403，Redis 中写入封禁 key。

## 关键机制概览
- **路径规则**：在两个过滤器中分别维护可疑路径集合和即时封禁集合，匹配逻辑相同。【F:src/main/java/com/example/mvc/BruteForceShieldFilter.java†L47-L70】【F:src/main/java/com/example/webflux/BruteForceShieldWebFluxFilter.java†L38-L70】
- **登录豁免**：若请求头 `your_app_account` 携带可解析的 JWT 且含 `id` 声明，则跳过风控。【F:src/main/java/com/example/mvc/BruteForceShieldFilter.java†L74-L83】【F:src/main/java/com/example/webflux/BruteForceShieldWebFluxFilter.java†L72-L83】
- **封禁策略**：触发规则时以 `brute_force_shield_ban:<ip>` 写入 Redis，封禁时间按 2ⁿ 递增，最长 64 天。【F:src/main/java/com/example/mvc/BruteForceShieldFilter.java†L113-L155】
- **异常状态统计**：对 404/405/400 响应计数，阈值达标封禁。【F:src/main/java/com/example/mvc/BruteForceShieldFilter.java†L89-L105】【F:src/main/java/com/example/webflux/BruteForceShieldWebFluxFilter.java†L89-L118】
- **代理支持**：可开启 `trustProxy` 读取 `X-Forwarded-For`、`X-Real-IP`、`CF-Connecting-IP` 头，适配反向代理架构。【F:src/main/java/com/example/mvc/BruteForceShieldFilter.java†L159-L178】【F:src/main/java/com/example/webflux/BruteForceShieldWebFluxFilter.java†L120-L148】

## 自定义示例
- **调整阈值/窗口**：在 Bean 初始化时调用流式 setter，例如 `setSuspiciousHitThreshold(3)`、`setNotFoundWindow(Duration.ofHours(2))`。
- **动态白名单**：运行时调用 `addWhitelistIp("203.0.113.1")`；支持在注册阶段预置多个可信 IP。
- **信任代理**：将 `setTrustProxy(true)` 以启用前置代理的真实客户端 IP 获取逻辑。

## Redis Key 约定
- 前缀：`Your_AppNamebrute_force_shield_`
- `ban:<ip>`：封禁标记与剩余 TTL。
- `ban_count:<ip>`：累计被封禁次数，用于指数回退计算。
- `counter:susp:<ip>` 与 `counter:nf:<ip>`：可疑路径/异常状态计数。

## 适合用于
- 演示如何在 Spring Boot 3（MVC/WebFlux）中实现简单的防暴力扫描过滤器。
- 课堂或博客示例，帮助理解 Redis 计数、防护阈值与封禁策略的组合。
