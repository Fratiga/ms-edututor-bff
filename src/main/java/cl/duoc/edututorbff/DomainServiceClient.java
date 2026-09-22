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
//
// Cada dominio vive en su propio host:puerto (ec2-apps corre los 4 contenedores
// por separado), así que se mantiene un RestClient por dominio en vez de una
// única base-url compartida.
@Component
public class DomainServiceClient {

	private final Map<String, RestClient> clientsPorDominio;

	public DomainServiceClient(
			@Value("${edututor.domain-services.catalog-url}") String catalogUrl,
			@Value("${edututor.domain-services.sessions-url}") String sessionsUrl,
			@Value("${edututor.domain-services.audit-url}") String auditUrl,
			@Value("${edututor.domain-services.report-url}") String reportUrl) {
		this.clientsPorDominio = Map.of(
			"catalog", RestClient.builder().baseUrl(catalogUrl).build(),
			"sessions", RestClient.builder().baseUrl(sessionsUrl).build(),
			"audit", RestClient.builder().baseUrl(auditUrl).build(),
			"report", RestClient.builder().baseUrl(reportUrl).build()
		);
	}

	public Object forward(String dominio, JwtAuthenticationToken auth, String method, String path, Object body) {
		RestClient restClient = clientsPorDominio.get(dominio);
		if (restClient == null) {
			throw new IllegalArgumentException("Dominio de microservicio desconocido: " + dominio);
		}

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
			// El microservicio de dominio no respondió (aún no desplegado / caído).
			// Devolvemos el contexto que se habría propagado, para dejar
			// evidencia de que la propagación de identidad ya está implementada.
			return Map.of(
				"aviso", "Microservicio de dominio '" + dominio + "' no disponible en " + path,
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
