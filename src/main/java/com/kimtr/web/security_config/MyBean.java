package com.kimtr.web.security_config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.ModelAndView;

import com.kimtr.web.vo.MemberVO;

@Configuration
public class MyBean {
	
	@Bean
	public MemberVO getm() {
		return new MemberVO();
	}	
	
	@Bean
	public ModelAndView tt() {
		return new ModelAndView();
	}
	

}
