package com.kimtr.web.security_config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.kimtr.web.repository.IF_MemberDao;
import com.kimtr.web.vo.MemberVO;

import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {
	
	private final IF_MemberDao memberdao;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		try {
			System.out.println("DB값 가져오기"+username);
			MemberVO member = memberdao.selectOne(username);
			System.out.println(member +"님 로그인 시도");
			return User.builder().username(member.getId()).password(member.getPass()).roles(member.getRole()).build();  // 권한 1개
			//return User.builder().username(member.getId()).password(member.getPass()).roles(member.getRole(),"ADMIN").build(); //권한 2개
			// roles 메서드가 자동으로 Collection<GrantedAuthority> 타입으로 변경해 주는 것 같네.. 확신 90%
			// 아래 코드는 3번째 매개변수에서 타입에러 뜸.. 
			//return new User(member.getId(),member.getPass(), member.getRole());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
/*
 * 
UserDetailsService 란?
Spring Security에서 유저의 정보를 가져오는 인터페이스이다.
Spring Security에서 유저의 정보를 불러오기 위해서 구현해야하는 인터페이스로 기본 오버라이드 메서드는 **
@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
 */

