package cl.duoc.edututorbff;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Solo lectura, tal como pide el caso: "Consulta el timeline. Solo lectura."
@RestController
@RequestMapping("/api/audit")
@PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
public class AuditController {

	private final DomainServiceClient domainServiceClient;

	public AuditController(DomainServiceClient domainServiceClient) {
		this.domainServiceClient = domainServiceClient;
	}

	@GetMapping("/timeline")
	public Object timeline(JwtAuthenticationToken auth) {
		return domainServiceClient.forward("audit", auth, "GET", "/audit/timeline", null);
	}

	@GetMapping("/session/{id}")
	public Object porSesion(JwtAuthenticationToken auth, @PathVariable String id) {
		return domainServiceClient.forward("audit", auth, "GET", "/audit/session/" + id, null);
	}
}
