package security.filter;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import security.config.ApplicationUser;
import security.config.JwtConfig;

public class UsernamePasswordAuthenticationJwtFilter extends UsernamePasswordAuthenticationFilter{

	private JwtConfig jwtConfig;
	
	public UsernamePasswordAuthenticationJwtFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig) {
		super();
		this.setAuthenticationManager(authenticationManager);
		this.jwtConfig = jwtConfig;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		ObjectMapper mapper = new ObjectMapper();
		ApplicationUser user = null;
		try {
			user = mapper.readValue(request.getInputStream(), ApplicationUser.class);
		} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
		return this.getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername()
				, user.getPassword()));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		String token = Jwts.builder()
                .setSubject(authResult.getName())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 2 * 1000))
                .signWith(SignatureAlgorithm.HS256, jwtConfig.getSecuredKey())
                .compact();

        response.getWriter().write("Bearer " + token);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		response.getWriter().write("username or password error");
	}
	
}
