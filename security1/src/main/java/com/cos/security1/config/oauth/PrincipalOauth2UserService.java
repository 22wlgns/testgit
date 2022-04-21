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
	
	// 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션 생성
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		
		System.out.println("getClientRegistration:"+userRequest.getClientRegistration());
		System.out.println("getAccessToken:"+userRequest.getAccessToken().getTokenValue());
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		// 버튼 -> 로그인 창 -> 완료 -> code 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
		// Userequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필 받음
		System.out.println("getAttributes:"+oauth2User.getAttributes());
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
			
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response")); // response 안에 response가 또 있음
			
		} else if(userRequest.getClientRegistration().getRegistrationId().equals("kakao")) {
			
			System.out.println("카카오 로그인 요청");
			oAuth2UserInfo = new KakaoUserInfo(oauth2User.getAttributes());
			
		} else {
			
			System.out.println("현재 구글, 페이스북, 네이버, 카카오만 지원");
			
		}
		
		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider+"_"+providerId;
		String pw = bCryptPasswordEncoder.encode("가나다");
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userMapper.findByUsername(username);
			
		
		if(userEntity == null) {
			System.out.println("로그인 최초");
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
			
			System.out.println("등록된 계정입니다.");
			
		}
	
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
	
}
