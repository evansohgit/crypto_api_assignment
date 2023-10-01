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
public class ValidateAppKeyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
            System.out.println("ValidateAppKeyFilter");
            String apiKey = request.getHeader("api-key");
            String appName = request.getParameter("app-name");

            HttpServletResponse res = (HttpServletResponse) response;
            if(apiKey == null || appName == null){
                res.setStatus(401);
                return;
            }
                
            // Check if api-key is valid for app-name in db
            Map<String, Object> app = InMemoryDB.getAppByName(appName);
            if(app == null){
                res.setStatus(401);
                return;
            }
            if(!app.get("api_key").equals(apiKey)){
                res.setStatus(401);
                return;
            }      
            filterChain.doFilter(request, response);
            

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Do not run filter for /onboardApp
        return request.getServletPath().matches("/onboardApp");
        
    }
    
}
