package cl.duoc.edututorbff;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
			.cors(Customizer.withDefaults())
			.authorizeHttpRequests(a -> a.anyRequest().authenticated())
			.oauth2ResourceServer(o -> o.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
		return http.build();
	}

	// Entra emite los App Roles en el claim "roles" (arreglo de strings), no en
	// "scp"/"scope" como los scopes delegados. El valor del rol en Azure es
	// "Admin"/"Coordinador"/etc., pero el equipo acordó ROLE_ADMIN,
	// ROLE_COORDINADOR, etc. en mayúsculas — de ahí el toUpperCase().
	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter(jwt -> {
			List<String> roles = jwt.getClaimAsStringList("roles");
			if (roles == null) {
				return List.of();
			}
			return roles.stream()
				.map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
				.collect(Collectors.toList());
		});
		return converter;
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration c = new CorsConfiguration();
		// El frontend oficial (artifacts/edututor) es Vite + React en el 5173,
		// no Angular — se deja 4200 también por si se prueba con otro cliente local.
		c.setAllowedOrigins(List.of("http://localhost:5173", "http://localhost:4200"));
		// Frontend productivo servido como sitio estático S3 (sin CloudFront/HTTPS).
		c.setAllowedOriginPatterns(List.of("http://*.s3-website*.amazonaws.com"));
		c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		// El frontend también envía X-User-Id/X-User-Role (el BFF los ignora para
		// autorización real, que sale del JWT, pero el preflight igual los exige).
		c.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-User-Id", "X-User-Role"));
		UrlBasedCorsConfigurationSource s = new UrlBasedCorsConfigurationSource();
		s.registerCorsConfiguration("/**", c);
		return s;
	}
}
