package com.cos.security1.model;

import java.security.Timestamp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@ToString
@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {
	private int id;
	private String username;
	private String pw;
	private String email;
	private String role;
	private String provider; // google
	private String providerId; // google 고유번호
	private Timestamp createDate;
	
}