package Security_Scanner.Security_Scanner.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.Test;

class TlsSecurityScannerTest {

	private static final String URL = "https://example.com";

	private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

	private final TlsSecurityScanner scanner = new TlsSecurityScanner(null);

	@Test
	void acceptsValidCertificate() {
		assertEquals(List.of(), codes(evaluate(valid(), true, true, List.of())));
	}

	@Test
	void reportsExpiredCertificateWithoutUntrustedDuplicate() {
		assertEquals(List.of("TLS_CERTIFICATE_EXPIRED"),
				codes(evaluate(validUntil(NOW.minus(1, ChronoUnit.DAYS)), false, true, List.of())));
	}

	@Test
	void reportsCertificateExpiringSoon() {
		assertEquals(List.of("TLS_CERTIFICATE_EXPIRING_SOON"),
				codes(evaluate(validUntil(NOW.plus(29, ChronoUnit.DAYS)), true, true, List.of())));
	}

	@Test
	void acceptsCertificateExpiringAfterThreshold() {
		assertEquals(List.of(),
				codes(evaluate(validUntil(NOW.plus(31, ChronoUnit.DAYS)), true, true, List.of())));
	}

	@Test
	void reportsCertificateNotYetValid() {
		TlsSecurityScanner.CertificateInfo certificate = certificate(
				NOW.plus(1, ChronoUnit.DAYS), NOW.plus(90, ChronoUnit.DAYS), false);

		assertEquals(List.of("TLS_CERTIFICATE_NOT_YET_VALID"),
				codes(evaluate(certificate, false, true, List.of())));
	}

	@Test
	void reportsSelfSignedCertificateWithoutUntrustedDuplicate() {
		TlsSecurityScanner.CertificateInfo certificate = certificate(
				NOW.minus(1, ChronoUnit.DAYS), NOW.plus(90, ChronoUnit.DAYS), true);

		assertEquals(List.of("TLS_CERTIFICATE_SELF_SIGNED"),
				codes(evaluate(certificate, false, true, List.of())));
	}

	@Test
	void reportsUntrustedChain() {
		assertEquals(List.of("TLS_CERTIFICATE_UNTRUSTED"),
				codes(evaluate(valid(), false, true, List.of())));
	}

	@Test
	void reportsHostnameMismatchForTrustedChain() {
		assertEquals(List.of("TLS_HOSTNAME_MISMATCH"),
				codes(evaluate(valid(), true, false, List.of())));
	}

	@Test
	void reportsWeakProtocolsInEvidence() {
		List<FindingDraft> findings = evaluate(valid(), true, true, List.of("TLSv1.1", "TLSv1"));

		assertEquals(List.of("TLS_WEAK_PROTOCOL"), codes(findings));
		assertTrue(findings.get(0).evidence().get(0).content().contains("TLSv1.1, TLSv1"));
	}

	private List<FindingDraft> evaluate(TlsSecurityScanner.CertificateInfo certificate,
			boolean chainTrusted, boolean hostnameMatches, List<String> weakProtocols) {

		return scanner.evaluate(URL, certificate, chainTrusted, hostnameMatches, weakProtocols, NOW);
	}

	private TlsSecurityScanner.CertificateInfo valid() {
		return validUntil(NOW.plus(90, ChronoUnit.DAYS));
	}

	private TlsSecurityScanner.CertificateInfo validUntil(Instant notAfter) {
		return certificate(NOW.minus(30, ChronoUnit.DAYS), notAfter, false);
	}

	private TlsSecurityScanner.CertificateInfo certificate(Instant notBefore, Instant notAfter, boolean selfSigned) {
		return new TlsSecurityScanner.CertificateInfo(
				"CN=example.com",
				"CN=Test CA",
				notBefore,
				notAfter,
				"TLSv1.3",
				List.of("example.com"),
				selfSigned);
	}

	private List<String> codes(List<FindingDraft> findings) {
		return findings.stream()
				.map(finding -> finding.definition().code())
				.toList();
	}

}
