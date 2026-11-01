package Security_Scanner.Security_Scanner.service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.EvidenceType;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ScopeViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * HTTP-сканер: проверяет заголовки безопасности, cookie и использование HTTPS.
 * Не следует редиректам за пределы разрешённой области и не читает тело ответа.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security-scanner.http.enabled", havingValue = "true", matchIfMissing = true)
public class HttpSecurityScanner implements SecurityScanner {

	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

	private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

	private static final String USER_AGENT = "WebCraftSecurityScanner/1.0";

	private static final FindingDefinition MISSING_HSTS = new FindingDefinition(
			"MISSING_HSTS",
			"Отсутствует заголовок Strict-Transport-Security",
			"Ответ по HTTPS не содержит HSTS, поэтому браузер может выполнить запрос по незащищённому HTTP.",
			FindingCategory.HEADERS,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Добавьте заголовок Strict-Transport-Security: max-age=31536000; includeSubDomains.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security");

	private static final FindingDefinition MISSING_X_CONTENT_TYPE_OPTIONS = new FindingDefinition(
			"MISSING_X_CONTENT_TYPE_OPTIONS",
			"Отсутствует заголовок X-Content-Type-Options",
			"Браузер может определить тип содержимого самостоятельно, что допускает MIME-sniffing атаки.",
			FindingCategory.HEADERS,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Добавьте заголовок X-Content-Type-Options: nosniff.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options");

	private static final FindingDefinition MISSING_X_FRAME_OPTIONS = new FindingDefinition(
			"MISSING_X_FRAME_OPTIONS",
			"Отсутствует защита от встраивания в iframe",
			"Страницу можно встроить в чужой iframe, что открывает путь к clickjacking.",
			FindingCategory.HEADERS,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Добавьте X-Frame-Options: DENY или директиву Content-Security-Policy: frame-ancestors.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options");

	private static final FindingDefinition MISSING_CONTENT_SECURITY_POLICY = new FindingDefinition(
			"MISSING_CONTENT_SECURITY_POLICY",
			"Отсутствует Content-Security-Policy",
			"Без CSP браузер не ограничивает источники скриптов, стилей и фреймов, что повышает риск XSS.",
			FindingCategory.HEADERS,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Настройте Content-Security-Policy с явным списком разрешённых источников.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy");

	private static final FindingDefinition MISSING_REFERRER_POLICY = new FindingDefinition(
			"MISSING_REFERRER_POLICY",
			"Отсутствует Referrer-Policy",
			"Полный URL может утекать во внешние ресурсы через заголовок Referer.",
			FindingCategory.HEADERS,
			Severity.LOW,
			Confidence.HIGH,
			"Добавьте Referrer-Policy: strict-origin-when-cross-origin.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy");

	private static final FindingDefinition MISSING_PERMISSIONS_POLICY = new FindingDefinition(
			"MISSING_PERMISSIONS_POLICY",
			"Отсутствует Permissions-Policy",
			"Приложение не ограничивает доступ к камере, микрофону, геолокации и другим возможностям браузера.",
			FindingCategory.HEADERS,
			Severity.LOW,
			Confidence.MEDIUM,
			"Добавьте Permissions-Policy с запретом неиспользуемых возможностей.",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy");

	private static final FindingDefinition INSECURE_COOKIE = new FindingDefinition(
			"INSECURE_COOKIE",
			"Cookie без флагов безопасности",
			"Cookie передаётся без части флагов Secure, HttpOnly или SameSite, что повышает риск перехвата и CSRF.",
			FindingCategory.COOKIES,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Установите Secure, HttpOnly и SameSite=Lax или Strict для всех чувствительных cookie.",
			"https://owasp.org/www-community/controls/SecureCookieAttribute");

	private static final FindingDefinition SERVER_VERSION_DISCLOSURE = new FindingDefinition(
			"SERVER_VERSION_DISCLOSURE",
			"Заголовок Server раскрывает версию",
			"Ответ содержит версию веб-сервера, что упрощает подбор известных уязвимостей.",
			FindingCategory.INFORMATION_DISCLOSURE,
			Severity.LOW,
			Confidence.HIGH,
			"Скройте версию сервера или используйте общий заголовок Server без номера версии.",
			"https://owasp.org/www-project-web-security-testing-guide/");

	private static final FindingDefinition X_POWERED_BY_DISCLOSURE = new FindingDefinition(
			"X_POWERED_BY_DISCLOSURE",
			"Заголовок X-Powered-By раскрывает технологию",
			"Ответ сообщает используемый фреймворк или платформу, что помогает выбрать вектор атаки.",
			FindingCategory.INFORMATION_DISCLOSURE,
			Severity.LOW,
			Confidence.HIGH,
			"Удалите заголовок X-Powered-By на уровне приложения или reverse proxy.",
			"https://owasp.org/www-project-web-security-testing-guide/");

	private static final FindingDefinition NO_HTTPS_REDIRECT = new FindingDefinition(
			"NO_HTTPS_REDIRECT",
			"Сайт доступен по HTTP без перенаправления на HTTPS",
			"Итоговый ответ получен по незащищённому HTTP, трафик может быть перехвачен или изменён.",
			FindingCategory.TRANSPORT,
			Severity.HIGH,
			Confidence.HIGH,
			"Настройте постоянный редирект с HTTP на HTTPS и включите HSTS.",
			"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure");

	private static final List<FindingDefinition> DEFINITIONS = List.of(
			MISSING_HSTS,
			MISSING_X_CONTENT_TYPE_OPTIONS,
			MISSING_X_FRAME_OPTIONS,
			MISSING_CONTENT_SECURITY_POLICY,
			MISSING_REFERRER_POLICY,
			MISSING_PERMISSIONS_POLICY,
			INSECURE_COOKIE,
			SERVER_VERSION_DISCLOSURE,
			X_POWERED_BY_DISCLOSURE,
			NO_HTTPS_REDIRECT);

	private final AssetScopeService assetScopeService;

	private final HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(CONNECT_TIMEOUT)
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	@Override
	public ScannerType getType() {
		return ScannerType.HTTP;
	}

	@Override
	public List<FindingDefinition> getDefinitions() {
		return DEFINITIONS;
	}

	@Override
	public ScanResult execute(ScanContext context) {
		Instant startedAt = Instant.now();

		try {
			String url = assetScopeService.validateAndNormalize(context.baseUrl());
			Duration timeout = context.timeout() == null || context.timeout().isNegative()
					? DEFAULT_TIMEOUT
					: context.timeout();
			ResponseData response = fetch(url, timeout);

			List<FindingDraft> findings = evaluate(url, response.url(), response.headers());

			String message = "Проверен " + response.url()
					+ ", найдено находок: " + findings.size();

			return ScanResult.success(message, startedAt, findings);
		}
		catch (ScopeViolationException exception) {
			return ScanResult.failure(exception.getMessage(), startedAt);
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			return ScanResult.failure("Запрос прерван", startedAt);
		}
		catch (IOException exception) {
			return ScanResult.failure("Не удалось получить ответ: " + exception.getMessage(), startedAt);
		}
	}

	/**
	 * Проверяет заголовки ответа. Выделено отдельно, чтобы тестировать без сети.
	 */
	List<FindingDraft> evaluate(String originalUrl, String finalUrl, HttpHeaders headers) {
		List<FindingDraft> findings = new ArrayList<>();

		boolean https = finalUrl.regionMatches(true, 0, "https://", 0, 8);

		if (!https) {
			findings.add(FindingDraft.of(NO_HTTPS_REDIRECT, finalUrl,
					EvidenceDraft.of(EvidenceType.TEXT,
							"Итоговый ответ получен по HTTP: " + finalUrl
									+ ". Исходный адрес: " + originalUrl)));
		}

		if (https && !hasHeader(headers, "strict-transport-security")) {
			findings.add(missingHeader(MISSING_HSTS, finalUrl, "Strict-Transport-Security"));
		}

		if (!hasHeader(headers, "x-content-type-options")) {
			findings.add(missingHeader(MISSING_X_CONTENT_TYPE_OPTIONS, finalUrl, "X-Content-Type-Options"));
		}

		if (!hasHeader(headers, "x-frame-options") && !cspProtectsFraming(headers)) {
			findings.add(missingHeader(MISSING_X_FRAME_OPTIONS, finalUrl,
					"X-Frame-Options (и frame-ancestors в CSP)"));
		}

		if (!hasHeader(headers, "content-security-policy")) {
			findings.add(missingHeader(MISSING_CONTENT_SECURITY_POLICY, finalUrl, "Content-Security-Policy"));
		}

		if (!hasHeader(headers, "referrer-policy")) {
			findings.add(missingHeader(MISSING_REFERRER_POLICY, finalUrl, "Referrer-Policy"));
		}

		if (!hasHeader(headers, "permissions-policy")) {
			findings.add(missingHeader(MISSING_PERMISSIONS_POLICY, finalUrl, "Permissions-Policy"));
		}

		headers.firstValue("server").ifPresent(value -> {
			if (value.chars().anyMatch(Character::isDigit)) {
				findings.add(FindingDraft.of(SERVER_VERSION_DISCLOSURE, finalUrl,
						EvidenceDraft.of(EvidenceType.RESPONSE_HEADER,
								"Server: " + truncate(value, 300))));
			}
		});

		headers.firstValue("x-powered-by").ifPresent(value ->
				findings.add(FindingDraft.of(X_POWERED_BY_DISCLOSURE, finalUrl,
						EvidenceDraft.of(EvidenceType.RESPONSE_HEADER,
								"X-Powered-By: " + truncate(value, 300)))));

		findings.addAll(cookieFindings(finalUrl, headers));

		return findings;
	}

	private ResponseData fetch(String url, Duration timeout) throws IOException, InterruptedException {
		URI uri = URI.create(url);
		ResponseData response = get(uri, timeout);

		if (isRedirect(response.status()) && response.location() != null) {
			URI target = uri.resolve(response.location());

			if (sameHost(uri, target)) {
				try {
					String normalized = assetScopeService.validateAndNormalize(target.toString());
					return get(URI.create(normalized), timeout);
				}
				catch (ScopeViolationException exception) {
					log.debug("Редирект вне разрешённой области проигнорирован: {}", target, exception);
				}
			}
		}

		return response;
	}

	private ResponseData get(URI uri, Duration timeout) throws IOException, InterruptedException {
		HttpRequest request = HttpRequest.newBuilder(uri)
				.timeout(timeout)
				.header("User-Agent", USER_AGENT)
				.header("Accept", "text/html,application/xhtml+xml")
				.GET()
				.build();

		HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());

		return new ResponseData(
				uri.toString(),
				response.statusCode(),
				response.headers(),
				response.headers().firstValue("location").orElse(null));
	}

	private boolean hasHeader(HttpHeaders headers, String name) {
		return headers.firstValue(name).isPresent();
	}

	private boolean cspProtectsFraming(HttpHeaders headers) {
		return headers.firstValue("content-security-policy")
				.map(value -> value.toLowerCase(Locale.ROOT).contains("frame-ancestors"))
				.orElse(false);
	}

	private FindingDraft missingHeader(FindingDefinition definition, String url, String header) {
		return FindingDraft.of(definition, url,
				EvidenceDraft.of(EvidenceType.RESPONSE_HEADER,
						"Заголовок " + header + " отсутствует в ответе"));
	}

	private List<FindingDraft> cookieFindings(String url, HttpHeaders headers) {
		List<FindingDraft> findings = new ArrayList<>();

		for (String rawCookie : headers.allValues("set-cookie")) {
			CookieInfo cookie = parseCookie(rawCookie);

			List<String> missing = new ArrayList<>();
			if (!cookie.secure()) {
				missing.add("Secure");
			}
			if (!cookie.httpOnly()) {
				missing.add("HttpOnly");
			}
			if (!cookie.sameSite()) {
				missing.add("SameSite");
			}

			if (missing.isEmpty()) {
				continue;
			}

			String content = "Cookie " + cookie.name() + " без флагов: "
					+ String.join(", ", missing) + ". " + cookie.sanitized();

			findings.add(FindingDraft.of(INSECURE_COOKIE, url,
					EvidenceDraft.of(EvidenceType.RESPONSE_HEADER, truncate(content, 1000))));
		}

		return findings;
	}

	private CookieInfo parseCookie(String rawCookie) {
		String[] parts = rawCookie.split(";");
		String name = parts[0].split("=", 2)[0].trim();
		if (name.isEmpty()) {
			name = "?";
		}

		boolean secure = false;
		boolean httpOnly = false;
		boolean sameSite = false;

		StringBuilder sanitized = new StringBuilder(name).append("=<redacted>");

		for (int index = 1; index < parts.length; index++) {
			String attribute = parts[index].trim();
			if (attribute.isEmpty()) {
				continue;
			}

			sanitized.append("; ").append(attribute);

			String lower = attribute.toLowerCase(Locale.ROOT);
			if (lower.equals("secure")) {
				secure = true;
			}
			else if (lower.equals("httponly")) {
				httpOnly = true;
			}
			else if (lower.startsWith("samesite=")) {
				sameSite = true;
			}
		}

		return new CookieInfo(name, sanitized.toString(), secure, httpOnly, sameSite);
	}

	private boolean isRedirect(int status) {
		return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
	}

	private boolean sameHost(URI first, URI second) {
		return first.getHost() != null
				&& second.getHost() != null
				&& first.getHost().equalsIgnoreCase(second.getHost());
	}

	private String truncate(String value, int limit) {
		return value.length() <= limit ? value : value.substring(0, limit);
	}

	private record ResponseData(String url, int status, HttpHeaders headers, String location) {
	}

	private record CookieInfo(String name, String sanitized, boolean secure, boolean httpOnly, boolean sameSite) {
	}

}
