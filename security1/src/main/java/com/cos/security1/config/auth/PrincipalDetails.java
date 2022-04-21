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

// ��ť��Ƽ�� /login �ּ� ��û�� ���� ����ä�� �α����� �����Ŵ
// �α��� ������ �Ϸ�Ǹ� ��ť��Ƽ session�� ������� (Security ContextHolder)
// Authentication Ÿ�� ��ü
// Authentication �ȿ� User ������ �־����
// User ������Ʈ�� Ÿ�� -> UserDetails Ÿ�� ��ü

// Security Session -> Authentication -> UserDetails(PrincipalDetails)

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
	
	private User userEntity;
	private Map<String, Object> attributes;
	
	// �Ϲ� �α���
	public PrincipalDetails(User userEntity) {
		this.userEntity = userEntity;
	}

	// OAuth �α���
	public PrincipalDetails(User userEntity, Map<String, Object> attributes) {
		this.userEntity = userEntity;
		this.attributes = attributes;
	}
	
	public User getUser() {
		return userEntity;
	}
	
	// �ش� User�� ������ �����ϴ� ��
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
		
		// ����Ʈ���� 1�� ���� ȸ���� �α��� ���� �� �޸� �������� ��ȯ
		// DB�� logindate �߰��ϰ� user.getLoginDate
		// ���� �ð� - �α� �ð� -> 1�� �ʰ� return false;
		
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