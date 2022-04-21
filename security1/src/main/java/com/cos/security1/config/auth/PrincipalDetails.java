package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.security1.model.User;

import lombok.Data;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킴
// 로그인 진행이 완료되면 시큐리티 session을 만들어줌 (Security ContextHolder)
// Authentication 타입 객체
// Authentication 안에 User 정보가 있어야함
// User 오브젝트의 타입 -> UserDetails 타입 객체

// Security Session -> Authentication -> UserDetails(PrincipalDetails)

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
	
	private User userEntity;
	private Map<String, Object> attributes;
	
	// 일반 로그인
	public PrincipalDetails(User userEntity) {
		this.userEntity = userEntity;
	}

	// OAuth 로그인
	public PrincipalDetails(User userEntity, Map<String, Object> attributes) {
		this.userEntity = userEntity;
		this.attributes = attributes;
	}
	
	public User getUser() {
		return userEntity;
	}
	
	// 해당 User의 권한을 리턴하는 곳
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		
		List<GrantedAuthority> collect = new ArrayList<GrantedAuthority>();
		
		collect.add(new SimpleGrantedAuthority(userEntity.getRole()));
		
		return collect;
	}
	
	@Override
	public String getPassword() {
		return userEntity.getPw();
	}

	@Override
	public String getUsername() {
		return userEntity.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		
		// 사이트에서 1년 동안 회원이 로그인 안할 시 휴면 계정으로 전환
		// DB에 logindate 추가하고 user.getLoginDate
		// 현재 시간 - 로그 시간 -> 1년 초과 return false;
		
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return userEntity.getId()+"";
	}
	
}