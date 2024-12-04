package com.kimtr.web;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.servlet.ModelAndView;

@SpringBootTest
public class MyBean {
	
	@Autowired
	ModelAndView m;
	
	@Test
	public void tt() {
		assertNotNull(m);
		System.out.println(m);
	}

}
