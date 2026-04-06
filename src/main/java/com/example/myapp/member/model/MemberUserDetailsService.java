package com.example.myapp.member.model;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.example.myapp.member.service.IMemberService;

@Component
public class MemberUserDetailsService implements UserDetailsService {

    @Autowired
    IMemberService memberService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberService.selectMember(username);

        if (member == null) {
            throw new UsernameNotFoundException(username + " 사용자를 찾을 수 없습니다.");
        }

        return User.builder()
                .username(member.getUserid())
                .password(member.getPassword())
                .roles("USER")
                .build();
    }
}