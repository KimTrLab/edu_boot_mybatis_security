package com.kimtr.web.security_config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	// https://velog.io/@woosim34/Spring-Spring-Security-%EC%84%A4%EC%A0%95-%EB%B0%8F-%EA%B5%AC%ED%98%84SessionSpring-boot3.0-%EC%9D%B4%EC%83%81
	
	private final MyUserDetailsService myUserDetailsService;

    @Bean  // password빈 등록   >> MemberServiceImpl 파일에서  주입받음.
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http 
        .csrf((csrfConfig) ->   //csrf 무력화
               // csrfConfig.disable()
        		csrfConfig.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        ) // 1번
       /* .headers((headerConfig) ->
                headerConfig.frameOptions(frameOptionsConfig ->
                        frameOptionsConfig.disable()
                )
        )// 2번*/
        .authorizeHttpRequests((authorizeRequests) ->   //url mapping로 인가
                authorizeRequests
                        .requestMatchers("/", "/login**/**","/join**","/img/**").permitAll()
                        .requestMatchers("/forbidden").permitAll()
                        .requestMatchers("/top10/js").permitAll()
                        .requestMatchers("/board/**", "/view","/mod","/del").hasRole("USER")   // role은 database에 지정
                        .requestMatchers("/admins/**", "/study**").hasRole(Role.ADMIN.name())
                        .anyRequest().authenticated()
                      
        )// 3번
        .exceptionHandling((exceptionConfig) ->  // 401, 403예외처리 구문
                exceptionConfig
             //   .authenticationEntryPoint(unauthorizedEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
        ) // 401 403 관련 예외처리
        .formLogin((formLogin) ->   // 로그인시 파라미터 받고, 성공과 실패시 이동하는 url 환경 ㅓㄹ정
    		formLogin
            .loginPage("/login-form")  //login page url
            .usernameParameter("id")     //view에서 보낸 파라미터
            .passwordParameter("pass")   //view에서 보낸 파라미터
            //[해설] UsernamePasswordAuthenticationFilter 에서 
            //      authentication 인터페이스를 구현 받은 UsernamePasswordAuthenticationToken을 만든다.
            //      AuthenticationManager에게 위에서 만든 authentication을 전달한다.
            //      provider를 거쳐서, userdetailsservice를 호출. DB값을 가져와서 userdetails로 리턴,
            //      provider를 리턴받은 userdetails로  암호랑 role를 확인하여 UsernamePasswordAuthenticationToken을 만든다
            //      UsernamePasswordAuthenticationToken은 authentication의 구현체이다.
            //      UsernamePasswordAuthenticationFilter은 UsernamePasswordAuthenticationToken(authentication 구현체)로
            //      SecurityContext에 저장한다.
            //      [개인의견]Oauth2 인경우는 UsernamePasswordAuthenticationFilter를 커스터마이징해야 한다.
            .loginProcessingUrl("/login") //view에서 보낸 url, 즉 로그인 form action
            .defaultSuccessUrl("/login_success") //로그인 성공시 이동  url    >> 세션 작업을 할까? 고민중
            .failureForwardUrl("/login-form")    //로그인이 실패한 경우 (아이디 비번이 잘못된 경우)
        		)
        .logout((logoutConfig) ->
        	logoutConfig
        	.logoutUrl("/logout")
        	.logoutSuccessUrl("/")
        	.invalidateHttpSession(true)
        	.deleteCookies("JSESSIONID")
        );
       // .userDetailsService(myUserDetailsService);   // 인증절차 처리 
		return http.build();
	}	
	//로그인실패 등 인가에 대한 정보가 없을 때,  .failureForwardUrl("/login-form") 보다 우선권이 있는 듯 그래서 사용안하려고 함.   
	private final AuthenticationEntryPoint unauthorizedEntryPoint =      
            (request, response, authException) -> {
            	response.setStatus(HttpStatus.FORBIDDEN.value());
            	System.out.println("entrypoint");
            };

    // role관련 인가에서 막히는 경우
    private final AccessDeniedHandler accessDeniedHandler =     
            (request, response, accessDeniedException) -> {
           //     ErrorResponse fail = new ErrorResponse(HttpStatus.FORBIDDEN, "Spring security forbidden...");
            	System.out.println("denieHandler");
            	response.sendRedirect("/code_403");
          //      response.setStatus(HttpStatus.FORBIDDEN.value());
            };

  	@Getter
    @RequiredArgsConstructor
    public class ErrorResponse {
        private final HttpStatus status;
        private final String message;
    }

}
