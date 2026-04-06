package com.example.myapp.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	//FilterChain 등록
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		// csrf 비활성화
		http.csrf(csrfConfig -> csrfConfig.disable());
		
		// login 성공시
		http.formLogin(login -> login.loginPage("/member/login")
									.usernameParameter("userid")
									.defaultSuccessUrl("/"));
		
		//logout 성공시 : 로그인 페이지로 이동 및 기존 세션 무효과
		http.logout(logout -> logout.logoutUrl("/member/logout")
									.logoutSuccessUrl("/member/login")
									.invalidateHttpSession(true));
		
		//URL별 접근 권한 설정
		http.authorizeHttpRequests(authRequest -> authRequest
				.requestMatchers("/file/**").hasRole("ADMIN")
				.requestMatchers("/board/**").hasAnyRole("USER","ADMIN")
				.requestMatchers("/css/**", "/js/**","/images/**").permitAll()
				.requestMatchers("/member/insert").permitAll()
				.requestMatchers("/member/login").permitAll()
				.requestMatchers("/**").permitAll());
				
		return http.build();
	}
	
	//Test 등록
	@Bean
	@ConditionalOnMissingBean(UserDetailsService.class)
	InMemoryUserDetailsManager userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("foo").password("{noop}demo").roles("ADMIN").build(),
				User.withUsername("bar").password("{noop}demo").roles("USER").build(),
				User.withUsername("ted").password("{noop}demo").roles("USER","ADMIN").build()
				);
	}
	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	

}
