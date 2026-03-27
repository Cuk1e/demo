package com.example.demo.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class AuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 1. 获取本次请求的HTTP动词和具体路径
        String method = request.getMethod();
        String uri = request.getRequestURI();

        // 2. 手写细粒度放行规则
        // 规则A: POST请求且路径精确等于"/api/users", 放行(允许注册)
        boolean isCreateUser = "POST".equalsIgnoreCase(method) && "/api/users".equals(uri);
        // 规则B: GET请求且路径以"/api/users/"开头, 放行(允许查看)
        boolean isGetUser = "GET".equalsIgnoreCase(method) && uri.startsWith("/api/users/");

        // 满足任一合法公开规则, 直接放行, 无需查验Token
        if (isCreateUser || isGetUser) {
            return true;
        }

        // 3. 执行严格的Token校验(针对DELETE、PUT等敏感操作)
        String token = request.getHeader("Authorization");
        if (token == null || token.isEmpty()) {
            response.setContentType("application/json; charset=UTF-8");
            String errorJson = "{\"code\": 401, \"msg\": \"非法操作:敏感动作[" + method + "]需登录授权\"}";
            response.getWriter().write(errorJson);
            return false;
        }
        return true;
    }
}