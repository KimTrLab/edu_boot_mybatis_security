package com.kimtr.web.vo;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor 
public class MemberVO {
	// html의 name이름과 vo의 변수명과 데이터베이스 컬럼은
	// 일치해야 자동으로 매핑 해 준다. 
	String id = null;
	String pass =null;
	String tel = null;
	String email = null;
	String role=null;
	String name=null;

	@Override
	public String toString() {
		return "MemberVO [id=" + id + ", pass=" + pass + ", tel=" + tel + ", email=" + email + "]";
	}

}
