package cl.duoc.edututorbff;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/catalog")
public class CatalogController {

	private final DomainServiceClient domainServiceClient;

	public CatalogController(DomainServiceClient domainServiceClient) {
		this.domainServiceClient = domainServiceClient;
	}

	// Según el documento de arquitectura: /api/catalog/** es ADMIN/COORDINADOR,
	// no abierto a ESTUDIANTE.
	@GetMapping("/services")
	@PreAuthorize("hasAnyRole('ADMIN', 'COORDINADOR')")
	public Object listarServicios(JwtAuthenticationToken auth) {
		return domainServiceClient.forward("catalog", auth, "GET", "/catalog/services", null);
	}

	@PostMapping("/services")
	@PreAuthorize("hasRole('ADMIN')")
	public Object crearServicio(JwtAuthenticationToken auth, @RequestBody Map<String, Object> servicio) {
		return domainServiceClient.forward("catalog", auth, "POST", "/catalog/services", servicio);
	}

	@PutMapping("/services/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public Object actualizarServicio(JwtAuthenticationToken auth, @PathVariable String id, @RequestBody Map<String, Object> servicio) {
		return domainServiceClient.forward("catalog", auth, "PUT", "/catalog/services/" + id, servicio);
	}
}
