package com.example.myapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                // 정적 리소스
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.png").permitAll()

                // 로그인 필요 없는 페이지
                .requestMatchers("/", "/member/login", "/member/insert").permitAll()
                .requestMatchers("/board/cat/**", "/board/search/**").permitAll()

                // 로그인 필요한 페이지
                .requestMatchers("/file/**").authenticated()
                .requestMatchers("/board/write/**", "/board/update/**", "/board/reply/**", "/board/delete/**").authenticated()
                .requestMatchers("/member/update", "/member/delete", "/member/logout").authenticated()

                // 나머지는 일단 허용
                .anyRequest().permitAll()
            )
            .formLogin(login -> login
                .loginPage("/member/login")
                .loginProcessingUrl("/member/login")
                .usernameParameter("userid")
                .passwordParameter("password")
                .defaultSuccessUrl("/member/login")
                .failureUrl("/member/login?error")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/member/logout"))
                .logoutSuccessUrl("/member/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            );

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}