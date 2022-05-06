package io.ysf.springsecurityjwt.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.ysf.springsecurityjwt.dto.AuthenticateRequest;
import io.ysf.springsecurityjwt.dto.AuthenticateResponse;
import io.ysf.springsecurityjwt.services.JWTService;
import io.ysf.springsecurityjwt.services.MyUserDetailsService;

@RestController
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JWTService jwtService;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@PostMapping("/authenticate")
	public AuthenticateResponse authenticate(
			@RequestBody AuthenticateRequest authenticateRequest)
			throws Exception {
		try {
			Authentication temp = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(
							authenticateRequest.getUsername(),
							authenticateRequest.getPassword()));
			UserDetails userDetails = myUserDetailsService
					.loadUserByUsername(authenticateRequest.getUsername());
			String token = jwtService.generateToken(userDetails);
			AuthenticateResponse authenticationResponse = new AuthenticateResponse(
					token);
			return authenticationResponse;
		} catch (Exception e) {
			throw new Exception("Incorrect Username or Password!", e);
		}
	}
}
