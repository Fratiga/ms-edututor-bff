package cl.duoc.edututorbff;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

// Único punto por el que el BFF llama a los microservicios de dominio
// (sessions, catalog, report, audit). Cada llamada sale con el contexto del
// usuario autenticado en cabeceras propias — los microservicios de dominio no
// vuelven a hablar con Entra, confían en lo que el BFF ya validó.
@Component
public class DomainServiceClient {

	private final RestClient restClient;

	public DomainServiceClient(@Value("${edututor.domain-services.base-url}") String baseUrl) {
		this.restClient = RestClient.builder().baseUrl(baseUrl).build();
	}

	public Object forward(JwtAuthenticationToken auth, String method, String path, Object body) {
		Jwt jwt = auth.getToken();
		List<String> rolesList = jwt.getClaimAsStringList("roles");
		String roles = String.join(",", rolesList == null ? List.of() : rolesList);
		String correlationId = incomingCorrelationId();

		try {
			RestClient.RequestBodySpec req = restClient.method(org.springframework.http.HttpMethod.valueOf(method))
				.uri(path)
				.header("X-User-Id", jwt.getSubject())
				.header("X-User-Name", jwt.getClaimAsString("name"))
				.header("X-User-Roles", roles)
				.header("X-Correlation-Id", correlationId);

			return body == null
				? req.retrieve().body(Object.class)
				: req.body(body).retrieve().body(Object.class);
		} catch (RestClientException e) {
			// Los microservicios de dominio todavía no existen / no están desplegados.
			// Devolvemos el contexto que se habría propagado, para dejar
			// evidencia de que la propagación de identidad ya está implementada.
			return Map.of(
				"aviso", "Microservicio de dominio no disponible en " + path,
				"contexto_propagado", Map.of(
					"X-User-Id", jwt.getSubject(),
					"X-User-Name", jwt.getClaimAsString("name"),
					"X-User-Roles", roles,
					"X-Correlation-Id", correlationId
				)
			);
		}
	}

	// Respeta el X-Correlation-Id que ya venga desde el API Gateway; si no
	// llegó ninguno, el BFF inicia la cadena de trazabilidad él mismo.
	private String incomingCorrelationId() {
		var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		String existing = attrs == null ? null : attrs.getRequest().getHeader("X-Correlation-Id");
		return existing != null ? existing : UUID.randomUUID().toString();
	}
}
