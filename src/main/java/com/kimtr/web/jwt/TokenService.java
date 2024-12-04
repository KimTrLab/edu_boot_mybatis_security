package com.kimtr.web.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

//@Service
public class TokenService {
	
private static final String SECRET_KEY = "OnlyICanChangeMyLifeNoOneCanDoItForMe";
	
	/**
	 * 토큰 생성하기
	 * @return
	 */
	public String makeJwtToken() {
		Date now = new Date();
		Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
		
		return Jwts.builder()
				.setHeaderParam(Header.TYPE, Header.JWT_TYPE)
				.setIssuer("myteam")
				.setIssuedAt(now)
				.setExpiration(new Date(now.getTime() + Duration.ofMinutes(30).toMillis()))
				.claim("id", "myId")
				.claim("email", "myId@gmail.com")
				.signWith(key)
				.compact();
	}
	
	/**
	 * 토큰 복호화 하여 본문(Payload) 가져오기
	 * @param token
	 * @return
	 */
	public Claims parseJwtToken(String token) {
		Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
		
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
		System.out.println("claims = " + claims.toString());		
		return claims;
	}

}
