package Security_Scanner.Security_Scanner.service.asset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import Security_Scanner.Security_Scanner.config.ScanScopeProperties;
import Security_Scanner.Security_Scanner.exception.ScopeViolationException;

class AssetScopeServiceTest {

	private ScanScopeProperties properties;
	private AssetScopeService service;

	@BeforeEach
	void setUp() {
		properties = new ScanScopeProperties();
		properties.setAllowedHosts(List.of("8.8.8.8", "example.com"));
		properties.setAllowSubdomains(false);
		service = new AssetScopeService(properties);
	}

	@Test
	void acceptsAllowedPublicIp() {
		assertEquals("https://8.8.8.8/path", service.validateAndNormalize("https://8.8.8.8/path?x=1#frag"));
	}

	@Test
	void stripsDefaultPort() {
		assertEquals("https://8.8.8.8", service.validateAndNormalize("https://8.8.8.8:443"));
	}

	@Test
	void keepsNonDefaultPort() {
		assertEquals("https://8.8.8.8:8443", service.validateAndNormalize("https://8.8.8.8:8443"));
	}

	@Test
	void rejectsNonHttpScheme() {
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("ftp://8.8.8.8"));
	}

	@Test
	void rejectsBlankUrl() {
		assertThrows(ScopeViolationException.class, () -> service.validateAndNormalize(" "));
	}

	@Test
	void rejectsMalformedUrl() {
		assertThrows(ScopeViolationException.class, () -> service.validateAndNormalize("http://exa mple.com"));
	}

	@Test
	void rejectsUserInfo() {
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("https://user:pass@8.8.8.8"));
	}

	@Test
	void rejectsHostOutsideScope() {
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("https://not-allowed.org"));
	}

	@Test
	void rejectsSubdomainWhenDisabled() {
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("https://sub.example.com"));
	}

	@Test
	void rejectsLocalhostEvenIfAllowed() {
		properties.setAllowedHosts(List.of("localhost"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://localhost:8080"));
	}

	@Test
	void rejectsLoopbackIp() {
		properties.setAllowedHosts(List.of("127.0.0.1"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://127.0.0.1"));
	}

	@Test
	void rejectsPrivateIp() {
		properties.setAllowedHosts(List.of("10.0.0.1", "192.168.1.1", "172.16.0.1"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://10.0.0.1"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://192.168.1.1"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://172.16.0.1"));
	}

	@Test
	void rejectsCloudMetadataEndpoint() {
		properties.setAllowedHosts(List.of("169.254.169.254"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://169.254.169.254/latest/meta-data/"));
	}

	@Test
	void rejectsCgnatIp() {
		properties.setAllowedHosts(List.of("100.64.0.1"));
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("http://100.64.0.1"));
	}

	@Test
	void rejectsEmptyAllowedHosts() {
		properties.setAllowedHosts(List.of());
		assertThrows(ScopeViolationException.class,
				() -> service.validateAndNormalize("https://8.8.8.8"));
	}

}
