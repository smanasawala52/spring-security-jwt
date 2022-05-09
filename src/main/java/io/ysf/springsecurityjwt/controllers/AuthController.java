package io.ysf.springsecurityjwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.ysf.springsecurityjwt.dto.ERole;
import io.ysf.springsecurityjwt.dto.Role;
import io.ysf.springsecurityjwt.dto.User;
import io.ysf.springsecurityjwt.payload.request.LoginCodeRequest;
import io.ysf.springsecurityjwt.payload.request.LoginRequest;
import io.ysf.springsecurityjwt.payload.request.SignupRequest;
import io.ysf.springsecurityjwt.payload.response.MessageResponse;
import io.ysf.springsecurityjwt.payload.response.UserInfoResponse;
import io.ysf.springsecurityjwt.repositories.RoleRepository;
import io.ysf.springsecurityjwt.repositories.UserRepository;
import io.ysf.springsecurityjwt.services.UserDetailsImpl;
import io.ysf.springsecurityjwt.utils.JwtUtils;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	UserRepository userRepository;
	@Autowired
	RoleRepository roleRepository;
	@Autowired
	PasswordEncoder encoder;
	@Autowired
	JwtUtils jwtUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(new UserInfoResponse(
				userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles, userDetails.getCode()));
	}

	@PostMapping("/signincode")
	public ResponseEntity<?> authenticateUserCode(@Valid @RequestBody LoginCodeRequest loginCodeRequest) {
		User user = userRepository.findByCode(loginCodeRequest.getCode()).orElseThrow(
				() -> new UsernameNotFoundException("User Not Found with code: " + loginCodeRequest.getCode()));
		if (user != null) {
			LoginRequest loginRequest = new LoginRequest();
			loginRequest.setUsername(user.getUsername());
			loginRequest.setPassword(user.getPassword());
			UserDetailsImpl userDetails = UserDetailsImpl.build(user);
			ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
			List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
					.collect(Collectors.toList());
			return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(new UserInfoResponse(
					userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles, userDetails.getCode()));
		}
		return ResponseEntity.badRequest()
				.body(new MessageResponse("Error: User not found with code: " + loginCodeRequest.getCode()));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}
		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
		}
		String randCode = getRandomNumberString();
		while (userRepository.existsByCode(randCode)) {
			randCode = getRandomNumberString();
		}
		// Create new user's account
		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()), randCode);
		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();
		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);
					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);
					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}
		user.setRoles(roles);
		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	@PostMapping("/signout")
	public ResponseEntity<?> logoutUser() {
		ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
				.body(new MessageResponse("You've been signed out!"));
	}

	public String getRandomNumberString() {
		// It will generate 6 digit random Number.
		// from 0 to 999999
		Random rnd = new Random();
		int number = rnd.nextInt(999999);

		// this will convert any number sequence into 6 character.
		return String.format("%06d", number);
	}
}
