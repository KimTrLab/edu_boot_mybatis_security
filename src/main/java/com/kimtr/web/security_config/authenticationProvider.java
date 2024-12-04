package com.kimtr.web.security_config;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class authenticationProvider implements AuthenticationProvider {

	// https://jaykaybaek.tistory.com/27
    @Autowired
    private UserDetailsService userDetailsService;
    private BCryptPasswordEncoder passwordEncoder;

    public authenticationProvider(BCryptPasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        User userDetails = (User)userDetailsService.loadUserByUsername(username);
        System.out.println("AuthenticationProvider");
        System.out.println(password+"(사용자 입력값)/"+userDetails.getPassword()+"(데이터저장값)/"+passwordEncoder.matches(password, userDetails.getPassword()));
        if(passwordEncoder.matches(password, userDetails.getPassword())==false) {
            throw new BadCredentialsException("Bad credentials");
        }

        // 임의로 role을 부여 하는 코드  --------------- 주석처리
       // List<GrantedAuthority> authorities = new ArrayList<>();
      //  authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        
        // userDetails에서 권한을 가져오는 코드 , userDetails 는 데이터베이스에서 role을 가져와서 user객체 만들때 role정보 포함
        Collection<GrantedAuthority> authorities=userDetails.getAuthorities();


//        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),userDetails.getPassword(),userDetails.getAuthorities());
        return new UsernamePasswordAuthenticationToken(userDetails,authentication.getCredentials(),authorities);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
