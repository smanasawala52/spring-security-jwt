package io.ysf.springsecurityjwt.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.ysf.springsecurityjwt.dto.MyUser;

@Service
public class MyUserDetailsService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<GrantedAuthority> l1 = new ArrayList<>();
		if (username.equalsIgnoreCase("admin")) {
			l1.add(new SimpleGrantedAuthority("ADMIN"));
		} else if (username.equalsIgnoreCase("user")) {
			l1.add(new SimpleGrantedAuthority("USER"));
		} else {
			l1 = null;
		}
		MyUser userDetails = new MyUser(username, "pass", true, true, true, true, l1, "");
		return userDetails;
	}

}
