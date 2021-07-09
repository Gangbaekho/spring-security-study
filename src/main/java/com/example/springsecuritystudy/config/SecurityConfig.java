package com.example.springsecuritystudy.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


//    이걸 사용하면은 AuthenticationManagerBuilder를 Customizing 할 수 있다.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }

//    어느 경로에 있는 것을 보안 적용할것인지 정할 수 있다.
//    httpBasic을 통해서 보안적용할 것인지
//    loginForm을 통해서 할 것인지
//    OAuth를 통해서 할 것인지 등을 정할 수 있다.
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        authentication을 httpBasic을 이용해서 하겠다는 말임.
        http.httpBasic();
//        이렇게 하면은 모든 경로에 있는 것을 Authentication 없이 사용할 수 있다.
//        http.authorizeRequests().anyRequest().permitAll();
        http.authorizeRequests().anyRequest().authenticated();
    }
}
