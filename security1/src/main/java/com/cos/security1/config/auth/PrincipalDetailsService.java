package com.cos.security1.config.auth;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.security1.mapper.UserMapper;
import com.cos.security1.model.User;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는 
// loadUserByUsername 함수가 실행

@Service
public class PrincipalDetailsService implements UserDetailsService {
	
	@Autowired
	private UserMapper userMapper;
	
	// 시큐리티 session(내부 Authentication(내부 UserDetails))
	// 함수 종료시 @AuthenticationPrincipal 어노테이션 생성
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 매개 변수 username과 html input name 무조건 username으로 통일!
		
		User userEntity = userMapper.findByUsername(username);
		
		if(userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		
		return null;
	}
	
}