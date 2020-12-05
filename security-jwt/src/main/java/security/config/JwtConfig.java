package security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
	private String securedKey;

	public String getSecuredKey() {
		return securedKey;
	}

	public void setSecuredKey(String securedKey) {
		this.securedKey = securedKey;
	}
	
}
