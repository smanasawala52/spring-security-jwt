package io.ysf.springsecurityjwt.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class MyUserDetails implements UserDetails {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8718745421521095275L;
	private String username;

	public MyUserDetails(String username) {
		this.username = username;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		List<GrantedAuthority> lst = new ArrayList<>();
		if (username.equalsIgnoreCase("admin")) {
			lst.add(new SimpleGrantedAuthority("ADMIN"));
		} else if (username.equalsIgnoreCase("user")) {
			lst.add(new SimpleGrantedAuthority("USER"));
		} else {
			// lst.add(new SimpleGrantedAuthority("ROLE_USER"));
		}
		return lst;
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return "pass";
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return this.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

}
