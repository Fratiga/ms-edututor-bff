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

	// Lectura abierta también a ESTUDIANTE: el flujo de agendar sesión (desde
	// Catálogo o desde Sesiones) necesita listar los servicios disponibles sin
	// importar el rol. Crear/editar servicios sigue siendo solo ADMIN.
	@GetMapping("/services")
	@PreAuthorize("hasAnyRole('ADMIN', 'COORDINADOR', 'ESTUDIANTE', 'AUDITOR')")
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

	// Directorio de tutores. Lectura para todos los roles (la página necesita los
	// nombres para mostrar quién dicta cada sesión); alta y cambios, solo ADMIN.
	@GetMapping("/tutors")
	@PreAuthorize("hasAnyRole('ADMIN', 'COORDINADOR', 'ESTUDIANTE', 'AUDITOR')")
	public Object listarTutores(JwtAuthenticationToken auth) {
		return domainServiceClient.forward("catalog", auth, "GET", "/catalog/tutors", null);
	}

	@PostMapping("/tutors")
	@PreAuthorize("hasRole('ADMIN')")
	public Object crearTutor(JwtAuthenticationToken auth, @RequestBody Map<String, Object> tutor) {
		return domainServiceClient.forward("catalog", auth, "POST", "/catalog/tutors", tutor);
	}

	@PutMapping("/tutors/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public Object actualizarTutor(JwtAuthenticationToken auth, @PathVariable String id, @RequestBody Map<String, Object> tutor) {
		return domainServiceClient.forward("catalog", auth, "PUT", "/catalog/tutors/" + id, tutor);
	}
}
