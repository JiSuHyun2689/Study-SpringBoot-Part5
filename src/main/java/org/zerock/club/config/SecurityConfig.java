package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Log4j2
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests().antMatchers("/sample/all").permitAll()
                .antMatchers("/sample/member").hasRole("USER");
        
        http.formLogin(); // 인가/인증 문제 시 로그인 화면 표출
        http.csrf().disable(); // csrf 토큰 생성 비활성화 -> 외부에서 REST 방식으로 이용하는 보안 설정 다루기 위해
        http.logout(); // 로그아웃
    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{

        // 사용자 계정 user2
        auth.inMemoryAuthentication().withUser("user2")
                .password("$2a$10$L9IC1R4hU0ibrW.8JsjUOuTkwnFV0fJw/UaFFItOzhsWaEVKBklwm").roles("USER");

    }
}
