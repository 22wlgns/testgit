package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

@Configuration
@EnableWebSecurity // ������ ��ť��Ƽ ���Ͱ� ������ ����ü�ο� ��ϵ�
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // @Secured Ȱ��ȭ, @PreAuthorize,@PostAuthorize Ȱ��ȭ
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	// ���� �α����� �Ϸ�� �� ��ó�� �ʿ�. Tip.�ڵ�X (��������ū + ����� ������ ���� O)
	// 1.�ڵ�ޱ�(����), 2.������ ��ū(����)
	// 3.����� ������ ������ ������, 4.������ ȸ�������� �ڵ����� �����Ű�� ��
	// 4-2.(�̸���, ��ȭ��ȣ, �̸�, ���̵�) ���θ� -> (�� �ּ�),��ȭ���� -> (vip���, �Ϲ� ���)
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable();
		
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated()
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll()
			.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login") // ��Ʈ�ѷ��� /login ��������
			.defaultSuccessUrl("/")
			.and()
			.oauth2Login()
			.loginPage("/loginForm")
			.userInfoEndpoint()
			.userService(principalOauth2UserService);
		
	}
	
}