package com.kimtr.web.controller;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.kimtr.web.service.IF_MemberService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;


@Controller
public class LoginController {
	@Autowired  // 주입 받기 위해서는 아래의 객체가 컨트롤러에 있어야 한다.
	IF_MemberService memberservice; 
	
	@GetMapping("logout")
	public String logout(HttpServletRequest request
			)throws Exception{
		HttpSession session = request.getSession();
		session.invalidate();  //세션을 무력화
		return "redirect:/";
	}
	//Spring security 변경 시점 부터 사용하지 않음
	/*
	@PostMapping("login")
	public String login(@RequestParam("id") String id,
			@RequestParam("pass") String pass,
			HttpServletRequest request)throws Exception{
		//클라이언트가 전송한 아이디와 패스워드가 디비에 있는지 확인
		//현재는 세션과 인터셉터가 목적이라서 윗 부분은 생략하고 진행
		// 아래 코드는 데이터베이스에서 가져온 값이 있을 경우만 실행되어야 함
		MemberVO nowUser = memberservice.selectOne(id);
		boolean flag=true;
		if(nowUser != null) {
			if(nowUser.getPass().equals(pass)) {
				// reqeust의 세션을 가져온다.
				HttpSession session = request.getSession();
				// 가져온 세션에 설정된 id변수의 값을 가져온다.
				Object nowid = session.getAttribute("id");
				// 만약 가져온 값이 있다면
				if(nowid != null) {
					// 기존의 세션값의 id변수의 값을 제거한다.
					session.removeAttribute("id");
				}
				// 세션에 변수 id를 저장한다. 
				session.setAttribute("id", id);
				flag=false;
			}
		}	
		if(flag) {
			return "redirect:/?msg=2";
		}else {
			return "redirect:/";
		}
	}*/
	@GetMapping("login-form")
	public String login_form()throws Exception{
		return "login/login";
	}
	@GetMapping("login_success")
	public String login_success(HttpServletRequest request)throws Exception{
		//인증(Authentication) : 증명, 유저가 누구인지 확인하는 것, 통상 회원가입하고 로그인하는 것을 말한다.
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String userid = "";//아이디
		String levels = "";//ROLE_ANONYMOUS
		Boolean enabled = false;
		//접근 주체(Principal) : 보호된 대상에 접근하는 유저
		Object principal = authentication.getPrincipal();
		if (principal instanceof UserDetails) {
			//인증이 처리되는 로직(아이디,암호를 스프링시큐리티 던져주고 인증은 스프링에서 알아서 해줌.)
			enabled = ((UserDetails)principal).isEnabled();
		}
		HttpSession session = request.getSession();//세션을 초기화 시켜줌.
		
		/*
		 * 
		 * 자바 8부터 추가된 기능으로 “컬렉션, 배열등의 저장 요소를 하나씩 참조하며 함수형 인터페이스(람다식)를 적용하며 반복적으로 처리할 수 있도록 해주는 기능“이다. 
		 * java api문서를 보면 java.util.Collection.stream() 에서 찾을 수 있다. 이 정의에서 다시 ‘컬렉션’이란 무엇일까 궁금해진다.
		 * 
		 * 불필요한 코딩(for, if 문법)을 걷어낼 수 있고 직관적이기 때문에 가독성이 좋아진다. 주로 Collection 과 Array에서 사용된다고 함.

		stream 사용 전
		for(int i = 0 ; i < list.size() ; i++){
    		answer[i] = list.get(i);
		}
		stream 사용
		return list.stream().mapToInt(i -> i.intValue()).toArray();
		용 예시를 보면 알 수 있듯이 계속해서 .으로 쭉- 이어나갈 수 있다. 즉 파이프라인 구조를 쓴다.		


		 */
		if (enabled) { //인증처리가 완료된 사용자의 권한체크(아래)
			Collection<? extends GrantedAuthority>  authorities = authentication.getAuthorities();
			System.out.println("Authentication 의  권한 : "+authorities.size());
		//	System.out.println(authorities.stream().map(o -> o.getAuthority().toString()));  
			
			authorities.stream().forEach(o -> System.out.println(o.getAuthority()));
			
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ANONYMOUS")).findAny().isPresent())
			{
				levels = "ANONYMOUS";
			}else {
				System.out.println("1");
			}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_USER")).findAny().isPresent())
			{
				levels = "USER";
			}else {
				System.out.println("2");
			}
			if(authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ADMIN")).findAny().isPresent())
			{
				levels = "ADMIN";
			}else {
				System.out.println("3");
			}
			userid =((UserDetails)principal).getUsername();
			//로그인 세션 저장
			session.setAttribute("session_enabled", enabled);//인증확인
			session.setAttribute("session_userid", userid);//사용자아이디
			session.setAttribute("session_levels", levels);//사용자권한
			//=========== 상단은 스프링시큐리티에서 기본제공하는 세션 변수처리
			//=========== 하단은 우리가 추가한는 세션 변수처리
        	}
		return "home";
	}

}
