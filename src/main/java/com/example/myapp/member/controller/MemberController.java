package com.example.myapp.member.controller;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;

import com.example.myapp.member.MemberValidator;
import com.example.myapp.member.model.Member;
import com.example.myapp.member.service.IMemberService;

import jakarta.servlet.http.HttpSession;

@Controller
public class MemberController {
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	IMemberService memberService;

	@Autowired
	MemberValidator memberValidator;

	@Autowired
	PasswordEncoder passwordEncoder;

	@InitBinder
	private void initBinder(WebDataBinder binder) {
		binder.setValidator(memberValidator);
	}

	@GetMapping(value = "/member/insert")
	public String insertMember(HttpSession session, Model model) {
		String csrfToken = UUID.randomUUID().toString();
		session.setAttribute("csrfToken", csrfToken);
		logger.info("/member/insert, GET");
		model.addAttribute("member", new Member());
		return "member/form";
	}

	@PostMapping(value = "/member/insert")
	public String memberInsert(@Validated Member member, BindingResult result, String csrfToken, HttpSession session,
			Model model) {

		if (csrfToken == null || "".equals(csrfToken)) {
			throw new RuntimeException("CSRF 토큰이 없습니다.");
		} else if (!csrfToken.equals(session.getAttribute("csrfToken"))) {
			throw new RuntimeException("잘 못된 접근");
		}

		if (result.hasErrors()) {
			model.addAttribute("member", member);
			return "member/form";
		}

		try {
			if (!member.getPassword().equals(member.getPassword2())) {
				model.addAttribute("member", member);
				model.addAttribute("message", "MEMBER_PW_RE");
				return "member/form";
			}

			member.setPassword(passwordEncoder.encode(member.getPassword()));
			memberService.insertMember(member);

		} catch (DuplicateKeyException e) {
			member.setUserid(null);
			model.addAttribute("member", member);
			model.addAttribute("message", "ID_ALREADY_EXIST");
			return "member/form";
		}

		session.invalidate();
		return "home";
	}

	@GetMapping(value = "/member/login")
	public String login() {
		return "member/login";
	}

	@GetMapping(value = "/member/update")
	public String updateMember(java.security.Principal principal, Model model) {
		String userid = principal.getName();
		Member member = memberService.selectMember(userid);
		model.addAttribute("member", member);
		model.addAttribute("message", "UPDATE_USER_INFO");
		return "member/update";
	}

	@PostMapping("/member/update")
	public String updateMember(Member member, java.security.Principal principal, Model model) {
		try {
			member.setUserid(principal.getName());
			member.setPassword(passwordEncoder.encode(member.getPassword()));
			memberService.updateMember(member);
			return "redirect:/member/logout";
		} catch (Exception e) {
			model.addAttribute("message", e.getMessage());
			return "member/error";
		}
	}

	@GetMapping("/member/delete")
	public String deleteMember(java.security.Principal principal, Model model) {
		String userid = principal.getName();
		Member member = memberService.selectMember(userid);
		model.addAttribute("member", member);
		model.addAttribute("message", "MEMBER_PW_RE");
		return "member/delete";
	}

	@PostMapping("/member/delete")
	public String deleteMember(String password,
	                           java.security.Principal principal,
	                           Model model) {
	    try {
	        String userid = principal.getName();
	        String dbpw = memberService.getPassword(userid);

	        if (password != null && passwordEncoder.matches(password, dbpw)) {
	            Member member = new Member();
	            member.setUserid(userid);
	            member.setPassword(dbpw);
	            memberService.deleteMember(member);
	            return "redirect:/member/logout";
	        } else {
	            model.addAttribute("message", "WRONG_PASSWORD");
	            return "member/delete";
	        }
	    } catch (Exception e) {
	        model.addAttribute("message", "DELETE_FAIL");
	        return "member/delete";
	    }
	}
}