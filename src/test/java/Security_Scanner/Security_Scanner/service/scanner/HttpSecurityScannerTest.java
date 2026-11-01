package Security_Scanner.Security_Scanner.service.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;

class HttpSecurityScannerTest {

	private final HttpSecurityScanner scanner = new HttpSecurityScanner(null);

	@Test
	void reportsMissingSecurityHeaders() {
		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com", headers("content-type", "text/html"));

		List<String> codes = codes(findings);

		assertTrue(codes.contains("MISSING_HSTS"));
		assertTrue(codes.contains("MISSING_X_CONTENT_TYPE_OPTIONS"));
		assertTrue(codes.contains("MISSING_X_FRAME_OPTIONS"));
		assertTrue(codes.contains("MISSING_CONTENT_SECURITY_POLICY"));
		assertTrue(codes.contains("MISSING_REFERRER_POLICY"));
		assertTrue(codes.contains("MISSING_PERMISSIONS_POLICY"));
		assertEquals(6, findings.size());
	}

	@Test
	void acceptsCompleteHeaderSet() {
		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com", secureHeaders());

		assertTrue(findings.isEmpty(), () -> "Ожидалось отсутствие находок, получено: " + codes(findings));
	}

	@Test
	void reportsHttpWithoutHttpsRedirect() {
		List<FindingDraft> findings = scanner.evaluate(
				"http://example.com", "http://example.com", headers(
						"x-content-type-options", "nosniff",
						"x-frame-options", "DENY",
						"content-security-policy", "default-src 'self'",
						"referrer-policy", "strict-origin-when-cross-origin",
						"permissions-policy", "geolocation=()"));

		List<String> codes = codes(findings);

		assertTrue(codes.contains("NO_HTTPS_REDIRECT"));
		assertFalse(codes.contains("MISSING_HSTS"));
		assertEquals(1, findings.size());
	}

	@Test
	void acceptsRedirectFromHttpToHttps() {
		List<FindingDraft> findings = scanner.evaluate(
				"http://example.com", "https://example.com", secureHeaders());

		assertTrue(findings.isEmpty(), () -> "Ожидалось отсутствие находок, получено: " + codes(findings));
	}

	@Test
	void cspFrameAncestorsReplacesXFrameOptions() {
		Map<String, List<String>> map = new LinkedHashMap<>();
		map.put("strict-transport-security", List.of("max-age=31536000"));
		map.put("x-content-type-options", List.of("nosniff"));
		map.put("content-security-policy", List.of("default-src 'self'; frame-ancestors 'none'"));
		map.put("referrer-policy", List.of("strict-origin-when-cross-origin"));
		map.put("permissions-policy", List.of("geolocation=()"));

		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com", HttpHeaders.of(map, (name, value) -> true));

		assertFalse(codes(findings).contains("MISSING_X_FRAME_OPTIONS"));
		assertTrue(findings.isEmpty(), () -> "Ожидалось отсутствие находок, получено: " + codes(findings));
	}

	@Test
	void reportsInsecureCookieWithoutLeakingValue() {
		Map<String, List<String>> map = secureHeadersMap();
		map.put("set-cookie", List.of("session=super-secret-token; Path=/"));

		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com", HttpHeaders.of(map, (name, value) -> true));

		assertEquals(List.of("INSECURE_COOKIE"), codes(findings));

		String content = findings.get(0).evidence().get(0).content();
		assertTrue(content.contains("Secure"));
		assertTrue(content.contains("HttpOnly"));
		assertTrue(content.contains("SameSite"));
		assertTrue(content.contains("<redacted>"));
		assertFalse(content.contains("super-secret-token"));
	}

	@Test
	void acceptsCookieWithAllFlags() {
		Map<String, List<String>> map = secureHeadersMap();
		map.put("set-cookie", List.of("session=abc; Secure; HttpOnly; SameSite=Lax"));

		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com", HttpHeaders.of(map, (name, value) -> true));

		assertTrue(findings.isEmpty(), () -> "Ожидалось отсутствие находок, получено: " + codes(findings));
	}

	@Test
	void reportsServerVersionButNotServerName() {
		List<FindingDraft> withVersion = scanner.evaluate(
				"https://example.com", "https://example.com",
				toHeaders(with(secureHeadersMap(), "server", "nginx/1.24.0")));
		assertTrue(codes(withVersion).contains("SERVER_VERSION_DISCLOSURE"));

		List<FindingDraft> withoutVersion = scanner.evaluate(
				"https://example.com", "https://example.com",
				toHeaders(with(secureHeadersMap(), "server", "nginx")));
		assertFalse(codes(withoutVersion).contains("SERVER_VERSION_DISCLOSURE"));
	}

	@Test
	void reportsXPoweredByDisclosure() {
		List<FindingDraft> findings = scanner.evaluate(
				"https://example.com", "https://example.com",
				toHeaders(with(secureHeadersMap(), "x-powered-by", "Express")));

		assertEquals(List.of("X_POWERED_BY_DISCLOSURE"), codes(findings));
	}

	private HttpHeaders secureHeaders() {
		return toHeaders(secureHeadersMap());
	}

	private HttpHeaders toHeaders(Map<String, List<String>> map) {
		return HttpHeaders.of(map, (name, value) -> true);
	}

	private Map<String, List<String>> secureHeadersMap() {
		Map<String, List<String>> map = new LinkedHashMap<>();
		map.put("strict-transport-security", List.of("max-age=31536000"));
		map.put("x-content-type-options", List.of("nosniff"));
		map.put("x-frame-options", List.of("DENY"));
		map.put("content-security-policy", List.of("default-src 'self'"));
		map.put("referrer-policy", List.of("strict-origin-when-cross-origin"));
		map.put("permissions-policy", List.of("geolocation=()"));
		return map;
	}

	private Map<String, List<String>> with(Map<String, List<String>> source, String name, String value) {
		Map<String, List<String>> copy = new LinkedHashMap<>(source);
		copy.put(name, List.of(value));
		return copy;
	}

	private HttpHeaders headers(String... pairs) {
		Map<String, List<String>> map = new LinkedHashMap<>();

		for (int index = 0; index < pairs.length; index += 2) {
			String name = pairs[index].toLowerCase(Locale.ROOT);
			map.computeIfAbsent(name, key -> new ArrayList<>()).add(pairs[index + 1]);
		}

		return HttpHeaders.of(map, (name, value) -> true);
	}

	private List<String> codes(List<FindingDraft> findings) {
		return findings.stream()
				.map(finding -> finding.definition().code())
				.toList();
	}

}
