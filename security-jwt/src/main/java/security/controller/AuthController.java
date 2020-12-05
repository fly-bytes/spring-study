package security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/admin")
public class AuthController {
	
	@GetMapping
	@PreAuthorize("hasAuthority('everything:operation')")
	public String admin() {
		return "admin";
	}
	
	@GetMapping(path = "/user")
	@PreAuthorize("hasAuthority('everything:read')")
	public String user() {
		return "user";
	}
}
