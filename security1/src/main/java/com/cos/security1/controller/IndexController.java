package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.mapper.UserMapper;
import com.cos.security1.model.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestBody;


@Controller
public class IndexController {
	
	@Autowired
	private UserMapper userMapper;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(Authentication authentication, 
											@AuthenticationPrincipal PrincipalDetails userDetails) {  // DI (������ ����) ���� ������ ���� ����
		System.out.println("/test/login___________________");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication: "+principalDetails.getUserEntity());
		System.out.println("username= "+userDetails.getUserEntity());
		
		return "���� ���� Ȯ��";
	}
	
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(Authentication authentication, 
												@AuthenticationPrincipal OAuth2User oauth) {  // DI (������ ����) ���� ������ ���� ����
		System.out.println("/test/oauth/login___________________");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication: "+oauth2User.getAttributes());
		System.out.println("OAuth2User: "+oauth.getAttributes());
		
		return "OAuth ���� ���� Ȯ��";
	}
	
	@GetMapping({"","/"})
	public String index() {
		return "index";
	}
	
	@GetMapping("/user")
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails: "+principalDetails.getUserEntity());
		System.out.println("principalDetails: "+principalDetails.getName());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		
		String rawPassword = user.getPw();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPw(encPassword);
		
		int result = userMapper.joinMember(user);
		
		if(result > 0) {
			return "redirect:/loginForm";
		}
		
		return "joinForm";
	}
	
	@Secured("ROLE_ADMIN") // �� ���� �ɰ� ���� ��� ���, �� �ܿ��� config���� �������� ó�� 
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "��������";
	}
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "������ ����";
	}

	@PostMapping("/infoConfirm") // 복호화 비밀번호 인증
	public String postMethodName(User user) {
		
		User user2 = userMapper.findByUsername(user.getUsername());
		
		if(bCryptPasswordEncoder.matches(user.getPw(), user2.getPw())) {

			return "index";

		} else {
			return "redirect:/user";
		}

	}
	
	/** Comma Test */
	@GetMapping("/comma")
	public String commaTest() {
		return "commaTest";
	}
	
	/** String으로 받아온 액수를 int로 반환 */
	@GetMapping("/commaData")
	public @ResponseBody int commaData(String commaNumber) {
		
		String num_s = commaNumber.replaceAll(",", "");

		int num = Integer.parseInt(num_s);

		return num;
	}
	
}