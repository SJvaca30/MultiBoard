package com.example.myapp.member.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;

import java.security.Principal;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.myapp.member.model.Member;
import com.example.myapp.member.service.IMemberService;
import com.example.myapp.member.MemberValidator;

@Controller
public class MemberController {

    private final SecurityFilterChain filterChain;
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	IMemberService memberService;
	
	@Autowired
	MemberValidator memberValidator;
	
	@Autowired
	PasswordEncoder passwordEncoder;


    MemberController(SecurityFilterChain filterChain) {
        this.filterChain = filterChain;
    }

	
	@InitBinder
	private void initBinder(WebDataBinder binder) {
		binder.setValidator(memberValidator);
	}
	

	@GetMapping(value="/member/insert")
	public String insertMember(HttpSession session, Model model) {
		String csrfToken = UUID.randomUUID().toString();
		session.setAttribute("csrfToken", csrfToken);
		logger.info("/member/insert, GET");
		model.addAttribute("member", new Member());
		return "member/form";
	}
	
	@PostMapping(value="/member/insert")
	public String memberInsert(@Validated Member member, BindingResult result,
			String csrfToken, HttpSession session, Model model) {
		if(csrfToken == null || "".equals(csrfToken)) {
			throw new RuntimeException("CSRF 토큰이 없습니다.");
		}else if(!csrfToken.equals(session.getAttribute("csrfToken"))) {
			throw new RuntimeException("잘못된 접근");
		}
		
		if(result.hasErrors()) {
			model.addAttribute("member", member);
			return "member/form";
		}
		
		try {
			//비빌번호와 비밀번호 확인이 맞는지
			if(!member.getPassword().equals(member.getPassword2())){
			model.addAttribute("member", member);
			model.addAttribute("message", "MEMBER_PW_RE");
			return "member/form";
			}
			
			String encodedPw = passwordEncoder.encode(member.getPassword());
			member.setPassword(encodedPw);
			memberService.insertMember(member);
		}catch(DuplicateKeyException e) {
			member.setUserid(null);
			model.addAttribute("member",member);
			model.addAttribute("message", "ID_ALREADY_EXIST");
			return "member/form";
		}
		session.invalidate();
		return "home";
	}
	

	@GetMapping(value="/member/login")
	public String login() {
		return "member/login";
	}
	
	@PostMapping(value="/member/login")
	public String login(String userid, String password, HttpSession session, Model model) {
		Member member = memberService.selectMember(userid);
		if(member != null) {
			logger.info(member.toString());
			String dbPassword = member.getPassword();
			if(dbPassword.equals(password)) { //비밀번호 일치
				session.setMaxInactiveInterval(600); //10분
				session.setAttribute("userid", userid);
				session.setAttribute("name", member.getName());
				session.setAttribute("email", member.getEmail());
			}else { //비밀번호가 다름
				session.invalidate();
				model.addAttribute("message", "WRONG_PASSWORD");
			}
		}else { //아이디가 없음
			session.invalidate();
			model.addAttribute("message", "USER_NOT_FOUND");
		}
		return "member/login";
	}
	

	@GetMapping(value="/member/logout")
	public String logout(HttpSession session, HttpServletRequest request) {
		session.invalidate(); //로그아웃
		return "home";
	}
	

	@GetMapping(value="/member/update")
	public String updateMember(Model model) {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String userid = auth.getName();
		if(userid != null && !userid.equals("")) {
			Member member = memberService.selectMember(userid);
			model.addAttribute("member", member);
			model.addAttribute("message", "UPDATE_USER_INFO");
			return "member/update";
		}else {
			//userid가 세션에 없을 때 (로그인하지 않았을 때)
			model.addAttribute("message", "NOT_LOGIN_USER");
			return "member/login";
		}
	}
	
	@PostMapping("/member/update")
	public String updateMember(@Validated Member member, BindingResult result, Principal principal, Model model) {
		try{
			
			String encodedPw = passwordEncoder.encode(member.getPassword());
			member.setPassword(encodedPw);
			memberService.updateMember(member);
			model.addAttribute("message", "UPDATED_MEMBER_INFO");
			model.addAttribute("member", member);
			return "member/login";
		}catch(Exception e){
			model.addAttribute("message", e.getMessage());
			e.printStackTrace();
			return "member/error";
		}
	}
	
	@GetMapping("/member/delete")
	public String deleteMember(Principal principal, Model model) {
		String userid = principal.getName();
		if(userid != null && !userid.equals("")) {
			Member member = memberService.selectMember(userid);
			model.addAttribute("member", member);
			model.addAttribute("message", "MEMBER_PW_RE");
			return "member/delete";
		}else {
			//userid가 세션에 없을 때 (로그인 하지 않았을 때)
			model.addAttribute("message", "NOT_LOGIN_USER");
			return "member/login";
		}
	}
	
	@PostMapping("/member/delete")
	public String deleteMember(String password, Principal principal, RedirectAttributes model) {
		try {
			Member member = new Member();
			member.setUserid(principal.getName());
			String dbpw = memberService.getPassword(member.getUserid());
			if(password != null && passwordEncoder.matches(password, dbpw)) {
				member.setPassword(dbpw);
				memberService.deleteMember(member) ;
				model.addFlashAttribute("message","DELETE_USER_INFO");
				return "redirect:/member/logout";
			}else {
				model.addAttribute("message", "WRONG_PASSWORD");
				return "member/delete";
			}
		}catch(Exception e){
			model.addAttribute("message", "DELETE_FAIL");
			e.printStackTrace();
			return "member/delete";
		}
	}
}