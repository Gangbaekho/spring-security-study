package com.example.springsecuritystudy.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MyAuthenticationProvider authenticationProvider;

//    초기에 이렇게 했음.
////    이걸 사용하면은 AuthenticationManagerBuilder를 Customizing 할 수 있다.
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
////        InMemory에 있는 user data를 사용해서 인증하겠다는 말임.
////        물론 나중에는 DB나 Redis로 바꿔야 할 것임.
//        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
////        tom 이라는 유저라 cruise라는 비밀번호를 사용할건데 암호화해서 일단 UserDetails를 만들어줬다.
////        추가로 권한은 read이다.
//        UserDetails user = User.withUsername("tom").password(passwordEncoder.encode("cruise")).authorities("read").build();
//
//        userDetailsService.createUser(user);


//        Bcrypt 암호화를 이용하겠다는 말임.
//        처음에는 passwordEncoder를 이용해서 직접 Bcrypt를 사용한다고 정의했으나
//        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());

//        이제는 Bean으로 PasswordEncoder를 등록했기 때문에 굳이 직접 안써줘도 알아서 해준다는 말임.
//        auth.userDetailsService(userDetailsService);
//
//
//    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//       이미 만들어진 authenticationProvider를 Bean으로 주입받아서 사용하게 됨.
        auth.authenticationProvider(authenticationProvider);
    }

    //    어느 경로에 있는 것을 보안 적용할것인지 정할 수 있다.
//    httpBasic을 통해서 보안적용할 것인지
//    loginForm을 통해서 할 것인지
//    OAuth를 통해서 할 것인지 등을 정할 수 있다.
    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        http.httpBasic();
//        이전에는 httpBasic으로 인증정보를 가져왔지만
//        이제는 formLogin 방식을 이용하겠다는 것임.
//        기본적으로 Spring에서 필요한 Form을 보여주고 입력받게 되어있음.
//        사용자가 입력하려고 하면은 이게 더 맞는 방식인것 같다.
//        httpBasic은 Http header에 직접 Authentication 필드에 주입해야 했기 때문에 불편하다.

        http.formLogin();
        http.authorizeRequests().anyRequest().authenticated();
    }

//    BcryptPasswordEncoder는 자주 사용할꺼라
//    Bean으로 등록하는것임.
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
