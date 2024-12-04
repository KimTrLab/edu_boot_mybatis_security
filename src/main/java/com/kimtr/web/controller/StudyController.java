package com.kimtr.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class StudyController {

	
	@GetMapping(value="/study_java")
	public String goJava() {
		return "/study/java";
	}
}
