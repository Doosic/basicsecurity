package io.security.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 인증 API 와 인가 API 에 대해서 추가적으로 설정할 수 있는 메서드
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        // 인가정책 - 어떠한 경우에도 인증을 받아야한다.
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        // 인증정책 - formLogin 방식으로 인증을 받는다.
        http
                .formLogin();
    }
}
