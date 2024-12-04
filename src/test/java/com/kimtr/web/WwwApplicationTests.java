package com.kimtr.web;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kimtr.web.repository.IF_MemberDao;
import com.kimtr.web.security_config.Role;
import com.kimtr.web.vo.MemberVO;

@SpringBootTest
class WwwApplicationTests {
	
	@Autowired
	IF_MemberDao aa;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Test
	@DisplayName("DI")
	void ditest() {
		assertNotNull(aa);
		assertNotNull(passwordEncoder);
	}
	
	@Test
	@DisplayName("단건 조회")
	void contextLoads() throws Exception {
		assertNotNull(aa);
		System.out.println(aa.selectOne("11").getId());
	}
	
	@Test
	@DisplayName("단건 입력")
	void add() throws Exception {
		MemberVO m = new MemberVO();
		m.setId("abc");
		m.setName("tt");
		m.setEmail("a");
		m.setRole("USER");
		m.setPass(passwordEncoder.encode("11"));
		m.setTel(Role.USER.name());
		aa.insertOne(m);
	}

}
