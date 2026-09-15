package cl.duoc.edututorbff;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sessions")
public class SessionsController {

	private final DomainServiceClient domainServiceClient;

	public SessionsController(DomainServiceClient domainServiceClient) {
		this.domainServiceClient = domainServiceClient;
	}

	@GetMapping
	@PreAuthorize("hasAnyRole('ADMIN', 'COORDINADOR', 'ESTUDIANTE')")
	public Object listar(JwtAuthenticationToken auth, @RequestParam Map<String, String> filtros) {
		return domainServiceClient.forward(auth, "GET", "/sessions", null);
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasAnyRole('ADMIN', 'COORDINADOR', 'ESTUDIANTE')")
	public Object obtener(JwtAuthenticationToken auth, @PathVariable String id) {
		return domainServiceClient.forward(auth, "GET", "/sessions/" + id, null);
	}

	@PostMapping
	@PreAuthorize("hasAnyRole('ESTUDIANTE', 'COORDINADOR', 'ADMIN')")
	public Object crear(JwtAuthenticationToken auth, @RequestBody Map<String, Object> sesion) {
		return domainServiceClient.forward(auth, "POST", "/sessions", sesion);
	}

	// Solo quien coordina o administra puede mover el estado de la sesión.
	@PutMapping("/{id}/status")
	@PreAuthorize("hasAnyRole('COORDINADOR', 'ADMIN')")
	public Object cambiarEstado(JwtAuthenticationToken auth, @PathVariable String id, @RequestBody Map<String, String> estado) {
		return domainServiceClient.forward(auth, "PUT", "/sessions/" + id + "/status", estado);
	}
}
