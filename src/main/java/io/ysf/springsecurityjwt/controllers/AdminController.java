package io.ysf.springsecurityjwt.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

	@GetMapping("/admin/hello")
	public String getHello() {
		return "Hello World ADMIN!";
	}

	@GetMapping("/admin")
	public String getHome() {
		return "Hello World ADMIN HOME PAGE!";
	}

}
