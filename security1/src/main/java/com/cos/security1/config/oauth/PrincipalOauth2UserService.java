package com.cos.security1.config.oauth;

import java.util.ArrayList;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.KakaoUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.mapper.UserMapper;
import com.cos.security1.model.User;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserMapper userMapper;
	
	// ���۷κ��� ���� userRequest �����Ϳ� ���� ��ó�� �Լ�
	// �Լ� ����� @AuthenticationPrincipal ������̼� ����
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		
		System.out.println("getClientRegistration:"+userRequest.getClientRegistration());
		System.out.println("getAccessToken:"+userRequest.getAccessToken().getTokenValue());
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		// ��ư -> �α��� â -> �Ϸ� -> code ����(OAuth-Client ���̺귯��) -> AccessToken ��û
		// Userequest ���� -> loadUser �Լ� ȣ�� -> ���۷κ��� ȸ�� ������ ����
		System.out.println("getAttributes:"+oauth2User.getAttributes());
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			
			System.out.println("���� �α��� ��û");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			
			System.out.println("���̽��� �α��� ��û");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			
			System.out.println("���̹� �α��� ��û");
			oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response")); // response �ȿ� response�� �� ����
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("kakao")) {
			
			System.out.println("īī�� �α��� ��û");
			oAuth2UserInfo = new KakaoUserInfo(oauth2User.getAttributes());
			
		} else {
			
			System.out.println("���� ����, ���̽���, ���̹�, īī���� ����");
			
		}
		
		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider+"_"+providerId;
		String pw = bCryptPasswordEncoder.encode("������");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userMapper.findByUsername(username);
			
		
		if(userEntity == null) {
			System.out.println("�α��� ����");
			userEntity = User.builder()
					.username(username)
					.pw(pw)
					.role(role)
					.email(email)
					.provider(provider)
					.providerId(providerId)
					.build();
			
			userMapper.joinOauthMember(userEntity);
			
		} else {
			
			System.out.println("��ϵ� �����Դϴ�.");
			
		}
	
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
	
}
