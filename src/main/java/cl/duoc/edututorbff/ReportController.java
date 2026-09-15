package cl.duoc.edututorbff;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/report")
@PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
public class ReportController {

	private final DomainServiceClient domainServiceClient;

	public ReportController(DomainServiceClient domainServiceClient) {
		this.domainServiceClient = domainServiceClient;
	}

	@GetMapping("/kpis")
	public Object kpis(JwtAuthenticationToken auth, @RequestParam(defaultValue = "last24h") String range) {
		return domainServiceClient.forward(auth, "GET", "/report/kpis?range=" + range, null);
	}

	@GetMapping("/top-services")
	public Object topServices(JwtAuthenticationToken auth, @RequestParam(defaultValue = "last7d") String range) {
		return domainServiceClient.forward(auth, "GET", "/report/top-services?range=" + range, null);
	}
}
