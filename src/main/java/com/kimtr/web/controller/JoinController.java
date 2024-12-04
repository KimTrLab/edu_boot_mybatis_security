package com.kimtr.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class JoinController {

	@GetMapping(value="/join")
	public String join()throws Exception{
		
		return "join/join";
	}
}
