package Security_Scanner.Security_Scanner.service.scanner.zap;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.EvidenceType;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.service.scanner.EvidenceDraft;
import Security_Scanner.Security_Scanner.service.scanner.FindingDefinition;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;

/**
 * Преобразует предупреждения ZAP в находки: отбрасывает всё вне области, группирует и редактирует секреты.
 */
final class ZapAlertMapper {

	private static final int MAX_EVIDENCE_PER_FINDING = 5;

	private static final String REDACTED = "<redacted>";

	private static final List<Redaction> REDACTIONS = List.of(
			new Redaction("(?i)(set-cookie:\\s*[^=;\\s]+=)[^;\\r\\n]*", "$1" + REDACTED),
			new Redaction("(?i)((?<![-\\w])cookie:\\s*)[^\\r\\n]*", "$1" + REDACTED),
			new Redaction("(?i)(\\bauthorization:\\s*)[^\\r\\n]*", "$1" + REDACTED),
			new Redaction("(?i)(\\bbearer\\s+)[A-Za-z0-9._~+/=-]+", "$1" + REDACTED),
			new Redaction("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*", REDACTED),
			new Redaction("(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|session(?:id)?|auth)"
					+ "([\"']?\\s*[=:]\\s*[\"']?)[^\\s\"'&;<>]+", "$1$2" + REDACTED));

	private ZapAlertMapper() {
	}

	private record Redaction(Pattern pattern, String replacement) {

		Redaction(String regex, String replacement) {
			this(Pattern.compile(regex), replacement);
		}

	}

	/**
	 * @return находки, отсортированные от более критичных к менее критичным
	 */
	static List<FindingDraft> toFindings(List<ZapAlert> alerts, URI target) {
		Map<String, Group> groups = new LinkedHashMap<>();

		for (ZapAlert alert : alerts) {
			if ("False Positive".equalsIgnoreCase(value(alert.confidence()))) {
				continue;
			}

			URI url = parse(alert.url());
			if (url == null || !isSameOrigin(url, target)) {
				continue;
			}

			String location = withoutQuery(url);
			String code = code(alert);

			groups.computeIfAbsent(code + " " + location, key -> new Group(definition(code, alert), location))
					.add(alert);
		}

		return groups.values().stream()
				.map(Group::toDraft)
				.sorted(Comparator.comparing(draft -> draft.definition().severity()))
				.toList();
	}

	static boolean isSameOrigin(URI url, URI target) {
		return target.getHost().equalsIgnoreCase(url.getHost()) && effectivePort(url) == effectivePort(target);
	}

	static String redact(String value) {
		String result = value(value);
		for (Redaction redaction : REDACTIONS) {
			result = redaction.pattern().matcher(result).replaceAll(redaction.replacement());
		}
		return result;
	}

	private static int effectivePort(URI uri) {
		// http и https на стандартных портах считаются одним сайтом: это обычный редирект на HTTPS.
		return uri.getPort() == 80 || uri.getPort() == 443 ? -1 : uri.getPort();
	}

	private static String code(ZapAlert alert) {
		String id = value(alert.alertRef()).isBlank() ? value(alert.pluginId()) : alert.alertRef();
		String sanitized = id.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_");
		return "ZAP_" + (sanitized.isBlank() ? "UNKNOWN" : truncate(sanitized, 90));
	}

	private static FindingDefinition definition(String code, ZapAlert alert) {
		return new FindingDefinition(
				code,
				truncate(value(alert.name()).isBlank() ? code : alert.name(), 300),
				truncate(value(alert.description()), 2000),
				category(value(alert.name())),
				severity(value(alert.risk())),
				confidence(value(alert.confidence())),
				truncate(value(alert.solution()), 2000),
				truncate(value(alert.reference()), 2000));
	}

	private static FindingCategory category(String name) {
		String lower = name.toLowerCase(Locale.ROOT);

		if (lower.contains("cookie")) {
			return FindingCategory.COOKIES;
		}
		if (lower.contains("header") || lower.contains("content security policy") || lower.contains("csp")) {
			return FindingCategory.HEADERS;
		}
		if (lower.contains("disclos") || lower.contains("leak")) {
			return FindingCategory.INFORMATION_DISCLOSURE;
		}
		if (lower.contains("https") || lower.contains("ssl") || lower.contains("tls")) {
			return FindingCategory.TRANSPORT;
		}
		return FindingCategory.CONFIGURATION;
	}

	private static Severity severity(String risk) {
		return switch (risk.toLowerCase(Locale.ROOT)) {
			case "high" -> Severity.HIGH;
			case "medium" -> Severity.MEDIUM;
			case "low" -> Severity.LOW;
			default -> Severity.INFO;
		};
	}

	private static Confidence confidence(String confidence) {
		return switch (confidence.toLowerCase(Locale.ROOT)) {
			case "high", "confirmed", "user confirmed" -> Confidence.HIGH;
			case "medium" -> Confidence.MEDIUM;
			default -> Confidence.LOW;
		};
	}

	private static URI parse(String url) {
		try {
			URI uri = new URI(value(url));
			return uri.getHost() == null ? null : uri;
		}
		catch (URISyntaxException exception) {
			return null;
		}
	}

	private static String withoutQuery(URI url) {
		String port = url.getPort() == -1 ? "" : ":" + url.getPort();
		String path = url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath();
		return truncate(url.getScheme() + "://" + url.getHost() + port + path, 2048);
	}

	private static String value(String value) {
		return value == null ? "" : value;
	}

	private static String truncate(String value, int limit) {
		return value.length() <= limit ? value : value.substring(0, limit);
	}

	private static final class Group {

		private final FindingDefinition definition;
		private final String url;
		private final List<EvidenceDraft> evidence = new ArrayList<>();

		private Group(FindingDefinition definition, String url) {
			this.definition = definition;
			this.url = url;
		}

		private void add(ZapAlert alert) {
			if (evidence.size() >= MAX_EVIDENCE_PER_FINDING) {
				return;
			}

			String content = "Правило ZAP: " + value(alert.pluginId());
			String other = redact(alert.other());
			if (!other.isBlank()) {
				content += "\n" + other;
			}

			String request = value(alert.method()) + " " + url;
			if (!value(alert.param()).isBlank()) {
				request += "\nПараметр: " + redact(alert.param());
			}

			evidence.add(new EvidenceDraft(
					EvidenceType.TEXT,
					truncate(content, 4000),
					truncate(request, 2000),
					truncate(redact(alert.evidence()), 2000)));
		}

		private FindingDraft toDraft() {
			return new FindingDraft(definition, url, evidence);
		}

	}

}
