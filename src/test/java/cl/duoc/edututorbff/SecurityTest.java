package cl.duoc.edututorbff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

// Seguridad del BFF: toda petición exige un JWT y los roles de Entra ID (claim
// "roles") se convierten en autoridades. No llama a ningún servicio de dominio.
@SpringBootTest
class SecurityTest {

	@Autowired
	WebApplicationContext contexto;

	@Autowired
	SecurityConfig config;

	MockMvc mvc;

	@BeforeEach
	void preparar() {
		mvc = MockMvcBuilders.webAppContextSetup(contexto).apply(springSecurity()).build();
	}

	private static Jwt token(Object roles) {
		Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none").subject("u1")
			.issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
		if (roles != null) {
			b.claim("roles", roles);
		}
		return b.build();
	}

	@Test
	void sinTokenLaPeticionSeRechazaConUnauthorized() throws Exception {
		mvc.perform(get("/api/report/kpis")).andExpect(status().isUnauthorized());
		mvc.perform(get("/api/sessions")).andExpect(status().isUnauthorized());
		mvc.perform(get("/api/audit/timeline")).andExpect(status().isUnauthorized());
	}

	@Test
	void unRolSinPermisoRecibeForbiddenAntesDeLlamarAlServicio() throws Exception {
		// los reportes son solo para ADMIN y AUDITOR
		mvc.perform(get("/api/report/kpis").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ESTUDIANTE"))))
			.andExpect(status().isForbidden());
		mvc.perform(get("/api/report/alerts").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ESTUDIANTE"))))
			.andExpect(status().isForbidden());
	}

	@Test
	void losRolesDeEntraSeConvierteEnAutoridadesEnMayusculas() {
		var convertidor = config.jwtAuthenticationConverter();

		assertThat(roles(convertidor.convert(token(List.of("Admin", "Coordinador"))).getAuthorities()))
			.containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_COORDINADOR");
	}

	@Test
	void unTokenSinRolesNoTieneAutoridades() {
		assertThat(roles(config.jwtAuthenticationConverter().convert(token(null)).getAuthorities())).isEmpty();
	}

	// Spring Security 7 agrega por su cuenta una autoridad FACTOR_BEARER: solo interesan los roles.
	private static List<String> roles(java.util.Collection<? extends GrantedAuthority> autoridades) {
		return autoridades.stream().map(GrantedAuthority::getAuthority).filter(a -> a.startsWith("ROLE_")).toList();
	}
}
