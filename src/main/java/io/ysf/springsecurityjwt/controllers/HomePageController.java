package io.ysf.springsecurityjwt.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomePageController {

	@GetMapping("/hello")
	public String getHello() {
		return "Hello World!";
	}

	@GetMapping("/")
	public String getHome() {
		return "Hello World HOME PAGE!";
	}

}
