package com.kimtr.web.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class BoardVO {
	String type;
	String username;
	String title;
	String content;
	String pass;
	String viewmember;
	String indate;
	String[] filename;
	String num;
}
