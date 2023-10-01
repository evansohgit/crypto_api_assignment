package com.evan.crypto.assignment.cryptoassignment;

import java.io.IOException;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AdminAuthFilter extends OncePerRequestFilter{

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        System.out.println("AdminAuthenticationFilter");
        String apiKey = request.getHeader("api-key");
        String apiToken = request.getHeader("api-token");

         // If api-key or api-token is not present, return 401
         if (apiKey == null || apiToken == null) {
            HttpServletResponse res = (HttpServletResponse) response;
            res.setStatus(401);
            return;
        }

        // relevant app given apikey and api token
        Map<String, Object> app = InMemoryDB.getAppByKeyToken(apiKey, apiToken);
        if (app == null) {
            HttpServletResponse res = (HttpServletResponse) response;
            res.setStatus(401);
            return;
        }
        // Raise 401 if app is not admin
        if ((boolean) app.get("is_admin") == false) {
            HttpServletResponse res = (HttpServletResponse) response;
            res.setStatus(401);
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // don't filter if url is /encrypt, /decrypt or /createSecretKey
        return !request.getServletPath().matches("/onboardApp");
        
    }

}
