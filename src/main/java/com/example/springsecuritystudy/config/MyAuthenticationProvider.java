package com.example.springsecuritystudy.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
public class MyAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String userName = authentication.getName();
//        authentication.getCredentials()는 Object를 Return하기 떄문에 toString을 써준것임.
        String password = authentication.getCredentials().toString();

        if("tom".equals(userName) && "cruise".equals(password)){
            return new UsernamePasswordAuthenticationToken(userName,password, Arrays.asList());
        }else{
            throw new BadCredentialsException("Invalid Username or Password");
        }

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
