package io.ysf.springsecurityjwt.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@GetMapping("/user/hello")
	public String getHello() {
		return "Hello World USER!";
	}

	@GetMapping("/user")
	public String getHome() {
		return "Hello World USER HOME PAGE!";
	}

}
