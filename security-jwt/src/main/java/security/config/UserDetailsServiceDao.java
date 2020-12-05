package security.config;

import java.util.List;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

@Service
public class UserDetailsServiceDao implements UserDetailsService {
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		try {
			return getUserDetailFromDb().stream().filter(x->x.getUsername().equals(username)).findFirst().orElseThrow(new Supplier<Throwable>() {
				@Override
				public Throwable get() {
					return null;
				}
			});
		} catch (Throwable throwable) {
			throwable.printStackTrace();
		}

		return null;
	}

	List<UserDetails> getUserDetailFromDb() {
		return Lists.newArrayList(
				User.builder().username("admin").password(passwordEncoder.encode("123")).roles("admin")
						.authorities("everything:operation").build(),
				User.builder().username("lbx").password(passwordEncoder.encode("123")).roles("user")
						.authorities("everything:read").build());
	}
}
