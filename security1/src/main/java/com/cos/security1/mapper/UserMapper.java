package com.cos.security1.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.cos.security1.model.User;

@Mapper
public interface UserMapper {
	
	int joinMember(User user);
	
	int joinOauthMember(User user);
	
	// findBy ��Ģ -> Username�� ����
	// select * from user where username = ? (username)
	// jpa query method
	User findByUsername(String username);
	
}