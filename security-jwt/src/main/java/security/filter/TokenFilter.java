package security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.collect.Maps;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import security.config.JwtConfig;

public class TokenFilter extends OncePerRequestFilter{

	private JwtConfig jwtConfig;
	
	
	public TokenFilter(JwtConfig jwtConfig) {
		super();
		this.jwtConfig = jwtConfig;
	}

	private Map<String, Collection<? extends GrantedAuthority>> authority = Maps.newHashMap();
	
	{
		authority.put("admin", Arrays.asList(new GrantedAuthority() {

			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;

			@Override
			public String getAuthority() {
				return "everything:operation";
			}
		}));
		
		authority.put("lbx", Arrays.asList(new GrantedAuthority() {

			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;

			@Override
			public String getAuthority() {
				return "everything:read";
			}
		}));
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = request.getHeader("Authorization");

        if (token == null || !token.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = null;
        
        try {
        	 authenticationToken = getAuthentication(token);
		} catch (Exception e) {
			throw new RuntimeException("token 无效");
		}
        
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(String token) {
	        Claims claims = Jwts.parser().setSigningKey(jwtConfig.getSecuredKey())
	                .parseClaimsJws(token.replace("Bearer ", ""))
	                .getBody();

	        //得到用户名
	        String username = claims.getSubject();

	        //得到过期时间
	        Date expiration = claims.getExpiration();

	        //判断是否过期
	        Date now = new Date();

	        if (now.getTime() > expiration.getTime()) {

	            throw new RuntimeException("该账号已过期,请重新登陆");
	        }

	        if (username != null) {
	            return new UsernamePasswordAuthenticationToken(username, null, authority.getOrDefault(username, Collections.EMPTY_LIST));
	        }
	        return null;
	    }
}
