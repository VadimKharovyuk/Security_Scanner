package Security_Scanner.Security_Scanner.service.scanner.zap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.service.scanner.EvidenceDraft;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;

class ZapAlertMapperTest {

	private static final URI TARGET = URI.create("https://example.com");

	@Test
	void mapsAlertFields() {
		FindingDraft draft = single(alert("10038-1", "Medium", "High", "https://example.com/page", "header"));

		assertEquals("ZAP_10038_1", draft.definition().code());
		assertEquals(Severity.MEDIUM, draft.definition().severity());
		assertEquals(Confidence.HIGH, draft.definition().confidence());
		assertEquals("https://example.com/page", draft.url());
	}

	@Test
	void mapsInformationalRiskAndConfirmedConfidence() {
		FindingDraft draft = single(alert("1", "Informational", "Confirmed", "https://example.com/", ""));

		assertEquals(Severity.INFO, draft.definition().severity());
		assertEquals(Confidence.HIGH, draft.definition().confidence());
	}

	@Test
	void usesPluginIdWithoutAlertRef() {
		FindingDraft draft = single(alert(null, "Low", "Low", "https://example.com/", ""));

		assertEquals("ZAP_10021", draft.definition().code());
	}

	@Test
	void dropsFalsePositives() {
		assertTrue(ZapAlertMapper.toFindings(
				List.of(alert("1", "High", "False Positive", "https://example.com/", "")), TARGET).isEmpty());
	}

	@Test
	void dropsAlertsOutsideAsset() {
		List<ZapAlert> alerts = List.of(
				alert("1", "High", "High", "https://evil.example.org/", ""),
				alert("1", "High", "High", "https://sub.example.com/", ""),
				alert("1", "High", "High", "https://example.com.evil.org/", ""),
				alert("1", "High", "High", "https://example.com:8443/", ""),
				alert("1", "High", "High", "not a url", ""),
				alert("1", "High", "High", null, ""));

		assertTrue(ZapAlertMapper.toFindings(alerts, TARGET).isEmpty());
	}

	@Test
	void keepsHttpAlertForHttpsAsset() {
		assertEquals(1, ZapAlertMapper.toFindings(
				List.of(alert("1", "Low", "Low", "http://example.com/", "")), TARGET).size());
	}

	@Test
	void requiresCustomPortOfAsset() {
		URI target = URI.create("https://example.com:8443");

		assertEquals(1, ZapAlertMapper.toFindings(
				List.of(alert("1", "Low", "Low", "https://example.com:8443/", "")), target).size());
		assertTrue(ZapAlertMapper.toFindings(
				List.of(alert("1", "Low", "Low", "https://example.com/", "")), target).isEmpty());
	}

	@Test
	void groupsSameRuleAndPathIgnoringQueryAndLimitsEvidence() {
		ZapAlert alert = alert("1", "Low", "Low", "https://example.com/a?token=secret-value&page=1", "x");

		List<FindingDraft> findings = ZapAlertMapper.toFindings(
				List.of(alert, alert, alert, alert, alert, alert, alert), TARGET);

		assertEquals(1, findings.size());
		assertEquals("https://example.com/a", findings.get(0).url());
		assertEquals(5, findings.get(0).evidence().size());
		assertFalse(findings.get(0).evidence().get(0).requestSnippet().contains("secret-value"));
	}

	@Test
	void treatsEmptyPathAsRoot() {
		List<FindingDraft> findings = ZapAlertMapper.toFindings(List.of(
				alert("1", "Low", "Low", "https://example.com", ""),
				alert("1", "Low", "Low", "https://example.com/", "")), TARGET);

		assertEquals(1, findings.size());
		assertEquals("https://example.com/", findings.get(0).url());
	}

	@Test
	void sortsBySeverity() {
		List<FindingDraft> findings = ZapAlertMapper.toFindings(List.of(
				alert("1", "Low", "Low", "https://example.com/", ""),
				alert("2", "High", "Low", "https://example.com/", ""),
				alert("3", "Medium", "Low", "https://example.com/", "")), TARGET);

		assertEquals(List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW),
				findings.stream().map(draft -> draft.definition().severity()).toList());
	}

	@Test
	void redactsSecretsInEvidence() {
		EvidenceDraft evidence = single(alert("1", "Low", "Low", "https://example.com/",
				"Set-Cookie: SESSION=abc123; Path=/")).evidence().get(0);

		assertEquals("Set-Cookie: SESSION=<redacted>; Path=/", evidence.responseSnippet());
	}

	@Test
	void redactsCommonSecretFormats() {
		assertEquals("Authorization: <redacted>", ZapAlertMapper.redact("Authorization: Basic dXNlcjpwYXNz"));
		assertEquals("Cookie: <redacted>", ZapAlertMapper.redact("Cookie: a=1; b=2"));
		assertEquals("Bearer <redacted>", ZapAlertMapper.redact("Bearer abc.def-123"));
		assertEquals("<redacted>", ZapAlertMapper.redact("eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl"));
		assertEquals("password=<redacted>&x=1", ZapAlertMapper.redact("password=hunter2&x=1"));
		assertEquals("\"api_key\": \"<redacted>\"", ZapAlertMapper.redact("\"api_key\": \"k-123\""));
		assertEquals("обычный текст", ZapAlertMapper.redact("обычный текст"));
	}

	@Test
	void chooseCategoryFromName() {
		ZapAlert cookie = new ZapAlert("Cookie No HttpOnly Flag", "1", "1", "Low", "Low",
				"https://example.com/", "GET", "", "", "", "", "", "");

		assertEquals(FindingCategory.COOKIES, single(cookie).definition().category());
	}

	@Test
	void truncatesLongValuesToColumnLimits() {
		String longText = "x".repeat(5000);
		ZapAlert alert = new ZapAlert(longText, "1", "1", "Low", "Low",
				"https://example.com/", "GET", "", longText, longText, longText, longText, longText);

		FindingDraft draft = single(alert);

		assertEquals(300, draft.definition().title().length());
		assertEquals(2000, draft.definition().description().length());
		assertEquals(2000, draft.evidence().get(0).responseSnippet().length());
		assertEquals(4000, draft.evidence().get(0).content().length());
	}

	private FindingDraft single(ZapAlert alert) {
		List<FindingDraft> findings = ZapAlertMapper.toFindings(List.of(alert), TARGET);
		assertEquals(1, findings.size());
		return findings.get(0);
	}

	private ZapAlert alert(String alertRef, String risk, String confidence, String url, String evidence) {
		return new ZapAlert("Rule", alertRef, "10021", risk, confidence, url, "GET", "", evidence, "", "d", "s", "r");
	}

}
