package com.cos.security1.config.auth;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.security1.mapper.UserMapper;
import com.cos.security1.model.User;

// ��ť��Ƽ �������� loginProcessingUrl("/login");
// /login ��û�� ���� �ڵ����� UserDetailsService Ÿ������ IoC �Ǿ��ִ� 
// loadUserByUsername �Լ��� ����

@Service
public class PrincipalDetailsService implements UserDetailsService {
	
	@Autowired
	private UserMapper userMapper;
	
	// ��ť��Ƽ session(���� Authentication(���� UserDetails))
	// �Լ� ����� @AuthenticationPrincipal ������̼� ����
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// �Ű� ���� username�� html input name ������ username���� ����!
		
		User userEntity = userMapper.findByUsername(username);
		
		if(userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		
		return null;
	}
	
}