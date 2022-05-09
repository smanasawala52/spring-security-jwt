package io.ysf.springsecurityjwt.controllers;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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
import io.ysf.springsecurityjwt.utils.CookieUtil;

@RestController
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JWTService jwtService;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	private static final String jwtTokenCookieName = "JWT-TOKEN";

	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticate(@RequestBody AuthenticateRequest authenticateRequest,
			HttpServletResponse response) throws Exception {
		try {
			Authentication temp = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticateRequest.getUsername(), authenticateRequest.getPassword()));
			UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticateRequest.getUsername());
			String token = jwtService.generateToken(userDetails);
			AuthenticateResponse authenticationResponse = new AuthenticateResponse(token);
			Cookie cookie = new Cookie("token", token);
			response.addCookie(cookie);
			// Return the token
			return ResponseEntity.ok(authenticationResponse);
		} catch (Exception e) {
			throw new Exception("Incorrect Username or Password!", e);
		}
	}

	@PostMapping("/validUser")
	public ResponseEntity<?> isValidUser(HttpServletRequest httpServletRequest, HttpServletResponse response)
			throws Exception {
		try {
			String token = CookieUtil.getValue(httpServletRequest, jwtTokenCookieName);
			if (token == null) {
				return null;
			}
			Cookie cookie = new Cookie("token", token);
			response.addCookie(cookie);
			AuthenticateResponse authenticationResponse = new AuthenticateResponse(token);
			return ResponseEntity.ok(authenticationResponse);
		} catch (Exception e) {
			throw new Exception("Incorrect Username or Password!", e);
		}
	}
}
