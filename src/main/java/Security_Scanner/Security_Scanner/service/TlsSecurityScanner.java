package Security_Scanner.Security_Scanner.service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

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
 * TLS-сканер: проверяет сертификат, цепочку доверия, соответствие хоста и версию протокола.
 * Для чтения сертификата используется отдельное соединение с доверием любому сертификату;
 * валидность цепочки проверяется стандартным trust store.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security-scanner.tls.enabled", havingValue = "true", matchIfMissing = true)
public class TlsSecurityScanner implements SecurityScanner {

	private static final Duration MAX_HANDSHAKE_TIMEOUT = Duration.ofSeconds(5);

	private static final int EXPIRING_SOON_DAYS = 30;

	private static final int DEFAULT_HTTPS_PORT = 443;

	private static final FindingDefinition CERTIFICATE_EXPIRED = new FindingDefinition(
			"TLS_CERTIFICATE_EXPIRED",
			"TLS-сертификат просрочен",
			"Срок действия сертификата истёк, браузеры будут показывать предупреждение и прерывать соединение.",
			FindingCategory.TRANSPORT,
			Severity.HIGH,
			Confidence.HIGH,
			"Выпустите новый сертификат и настройте автоматическое продление.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition CERTIFICATE_EXPIRING_SOON = new FindingDefinition(
			"TLS_CERTIFICATE_EXPIRING_SOON",
			"TLS-сертификат скоро истекает",
			"До окончания срока действия сертификата осталось меньше 30 дней.",
			FindingCategory.TRANSPORT,
			Severity.MEDIUM,
			Confidence.HIGH,
			"Продлите сертификат до истечения срока и настройте мониторинг даты окончания.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition CERTIFICATE_NOT_YET_VALID = new FindingDefinition(
			"TLS_CERTIFICATE_NOT_YET_VALID",
			"TLS-сертификат ещё не действует",
			"Дата начала действия сертификата находится в будущем, соединение будет отклонено.",
			FindingCategory.TRANSPORT,
			Severity.HIGH,
			Confidence.HIGH,
			"Проверьте системное время сервера и корректность выпущенного сертификата.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition CERTIFICATE_SELF_SIGNED = new FindingDefinition(
			"TLS_CERTIFICATE_SELF_SIGNED",
			"Самоподписанный TLS-сертификат",
			"Сертификат подписан сам собой и не подтверждён доверенным удостоверяющим центром.",
			FindingCategory.TRANSPORT,
			Severity.MEDIUM,
			Confidence.MEDIUM,
			"Используйте сертификат публичного или внутреннего доверенного CA.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition CERTIFICATE_UNTRUSTED = new FindingDefinition(
			"TLS_CERTIFICATE_UNTRUSTED",
			"Цепочка TLS-сертификатов не проходит проверку",
			"Стандартный trust store не смог построить доверенную цепочку до сертификата сервера.",
			FindingCategory.TRANSPORT,
			Severity.HIGH,
			Confidence.HIGH,
			"Передавайте полную цепочку сертификатов и используйте сертификат доверенного CA.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition HOSTNAME_MISMATCH = new FindingDefinition(
			"TLS_HOSTNAME_MISMATCH",
			"Сертификат не соответствует имени хоста",
			"CN или SAN сертификата не совпадает с запрошенным доменом, браузер отклонит соединение.",
			FindingCategory.TRANSPORT,
			Severity.HIGH,
			Confidence.HIGH,
			"Выпустите сертификат для правильного домена или добавьте его в SAN.",
			"https://developer.mozilla.org/en-US/docs/Glossary/Certificate");

	private static final FindingDefinition WEAK_PROTOCOL = new FindingDefinition(
			"TLS_WEAK_PROTOCOL",
			"Поддерживается устаревшая версия TLS",
			"Сервер принимает TLS 1.0 или TLS 1.1, которые считаются небезопасными.",
			FindingCategory.TRANSPORT,
			Severity.MEDIUM,
			Confidence.MEDIUM,
			"Отключите TLS 1.0 и TLS 1.1, оставив TLS 1.2 и TLS 1.3.",
			"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure");

	private static final List<FindingDefinition> DEFINITIONS = List.of(
			CERTIFICATE_EXPIRED,
			CERTIFICATE_EXPIRING_SOON,
			CERTIFICATE_NOT_YET_VALID,
			CERTIFICATE_SELF_SIGNED,
			CERTIFICATE_UNTRUSTED,
			HOSTNAME_MISMATCH,
			WEAK_PROTOCOL);

	private final AssetScopeService assetScopeService;

	@Override
	public ScannerType getType() {
		return ScannerType.TLS;
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
			URI uri = URI.create(url);

			if (!"https".equalsIgnoreCase(uri.getScheme())) {
				return ScanResult.success("TLS-проверка не применима для " + url, startedAt);
			}

			Duration timeout = context.timeout() == null || context.timeout().isNegative()
					? MAX_HANDSHAKE_TIMEOUT
					: context.timeout();

			List<FindingDraft> findings = inspect(url, uri, timeout);

			return ScanResult.success(
					"Проверен TLS " + uri.getHost() + ", найдено находок: " + findings.size(),
					startedAt,
					findings);
		}
		catch (ScopeViolationException exception) {
			return ScanResult.failure(exception.getMessage(), startedAt);
		}
		catch (GeneralSecurityException exception) {
			return ScanResult.failure("Ошибка TLS: " + exception.getMessage(), startedAt);
		}
		catch (IOException exception) {
			return ScanResult.failure("Не удалось установить TLS-соединение: " + exception.getMessage(), startedAt);
		}
	}

	/**
	 * Проверяет данные сертификата. Выделено отдельно, чтобы тестировать без сети.
	 */
	List<FindingDraft> evaluate(String url, CertificateInfo certificate,
			boolean chainTrusted, boolean hostnameMatches, boolean weakProtocolSupported, Instant now) {

		List<FindingDraft> findings = new ArrayList<>();

		boolean expired = certificate.notAfter().isBefore(now);
		boolean notYetValid = certificate.notBefore().isAfter(now);

		if (expired) {
			findings.add(withCertificate(CERTIFICATE_EXPIRED, url, certificate,
					"Сертификат истёк " + certificate.notAfter()));
		}
		else if (certificate.notAfter().isBefore(now.plus(EXPIRING_SOON_DAYS, ChronoUnit.DAYS))) {
			findings.add(withCertificate(CERTIFICATE_EXPIRING_SOON, url, certificate,
					"Сертификат истекает " + certificate.notAfter()));
		}

		if (notYetValid) {
			findings.add(withCertificate(CERTIFICATE_NOT_YET_VALID, url, certificate,
					"Сертификат начинает действовать " + certificate.notBefore()));
		}

		if (certificate.selfSigned()) {
			findings.add(withCertificate(CERTIFICATE_SELF_SIGNED, url, certificate,
					"Subject и Issuer совпадают: " + certificate.subject()));
		}

		// Если сертификат просрочен или самоподписан, причина недоверия уже известна.
		boolean knownCertificateProblem = expired || notYetValid || certificate.selfSigned();
		if (!chainTrusted && !knownCertificateProblem) {
			findings.add(withCertificate(CERTIFICATE_UNTRUSTED, url, certificate,
					"Стандартный trust store отклонил цепочку сертификатов"));
		}

		if (chainTrusted && !hostnameMatches) {
			findings.add(withCertificate(HOSTNAME_MISMATCH, url, certificate,
					"Сертификат не соответствует имени хоста"));
		}

		if (weakProtocolSupported) {
			findings.add(withCertificate(WEAK_PROTOCOL, url, certificate,
					"Сервер принимает устаревшую версию TLS"));
		}

		return findings;
	}

	private List<FindingDraft> inspect(String url, URI uri, Duration timeout)
			throws IOException, GeneralSecurityException {

		String host = uri.getHost();
		int port = uri.getPort() == DEFAULT_HTTPS_PORT || uri.getPort() == -1
				? DEFAULT_HTTPS_PORT
				: uri.getPort();

		Duration attemptTimeout = timeout.compareTo(MAX_HANDSHAKE_TIMEOUT) > 0
				? MAX_HANDSHAKE_TIMEOUT
				: timeout;

		// Повторная проверка области непосредственно перед сетевым соединением.
		assetScopeService.validateAndNormalize(url);

		SessionInfo session = handshake(host, port, true, false, attemptTimeout, null);
		CertificateInfo certificate = describe(session);

		boolean chainTrusted;
		try {
			handshake(host, port, false, false, attemptTimeout, null);
			chainTrusted = true;
		}
		catch (SSLException exception) {
			log.debug("Цепочка сертификатов не прошла проверку для {}", host, exception);
			chainTrusted = false;
		}

		boolean hostnameMatches = true;
		if (chainTrusted) {
			try {
				handshake(host, port, false, true, attemptTimeout, null);
			}
			catch (SSLException exception) {
				log.debug("Имя хоста не совпало с сертификатом для {}", host, exception);
				hostnameMatches = false;
			}
		}

		boolean weakProtocol = supportsWeakProtocol(host, port, attemptTimeout);

		return evaluate(url, certificate, chainTrusted, hostnameMatches, weakProtocol, Instant.now());
	}

	private SessionInfo handshake(String host, int port, boolean trustAll, boolean verifyHostname,
			Duration timeout, List<String> enabledProtocols) throws IOException {

		SSLContext context = trustAll ? trustAllContext() : SSLContext.getDefault();

		try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
			int timeoutMillis = (int) Math.min(timeout.toMillis(), Integer.MAX_VALUE);

			socket.connect(new InetSocketAddress(host, port), timeoutMillis);
			socket.setSoTimeout(timeoutMillis);

			SSLParameters parameters = socket.getSSLParameters();
			parameters.setEndpointIdentificationAlgorithm(verifyHostname ? "HTTPS" : null);
			socket.setSSLParameters(parameters);

			if (enabledProtocols != null) {
				socket.setEnabledProtocols(enabledProtocols.toArray(String[]::new));
			}

			socket.startHandshake();

			SSLSession sslSession = socket.getSession();
			X509Certificate certificate = (X509Certificate) sslSession.getPeerCertificates()[0];

			return new SessionInfo(sslSession.getProtocol(), certificate);
		}
	}

	private boolean supportsWeakProtocol(String host, int port, Duration timeout) {
		for (String protocol : List.of("TLSv1.1", "TLSv1")) {
			try {
				SessionInfo session = handshake(host, port, true, false, timeout, List.of(protocol));
				if (protocol.equals(session.protocol())) {
					return true;
				}
			}
			catch (IOException | RuntimeException exception) {
				log.debug("Протокол {} не согласован для {}", protocol, host, exception);
			}
		}

		return false;
	}

	private CertificateInfo describe(SessionInfo session) throws CertificateParsingException {
		X509Certificate certificate = session.certificate();

		List<String> alternativeNames = new ArrayList<>();
		Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames();

		if (subjectAlternativeNames != null) {
			for (List<?> entry : subjectAlternativeNames) {
				if (entry.size() >= 2) {
					alternativeNames.add(String.valueOf(entry.get(1)));
				}
			}
		}

		return new CertificateInfo(
				certificate.getSubjectX500Principal().getName(),
				certificate.getIssuerX500Principal().getName(),
				certificate.getNotBefore().toInstant(),
				certificate.getNotAfter().toInstant(),
				session.protocol(),
				alternativeNames,
				certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()));
	}

	private FindingDraft withCertificate(FindingDefinition definition, String url,
			CertificateInfo certificate, String summary) {

		String content = summary
				+ "\nSubject: " + truncate(certificate.subject(), 500)
				+ "\nIssuer: " + truncate(certificate.issuer(), 500)
				+ "\nДействителен: " + certificate.notBefore() + " — " + certificate.notAfter()
				+ "\nПротокол: " + certificate.protocol();

		if (!certificate.alternativeNames().isEmpty()) {
			content += "\nSAN: " + truncate(String.join(", ", certificate.alternativeNames()), 500);
		}

		return FindingDraft.of(definition, url,
				EvidenceDraft.of(EvidenceType.TLS_CERTIFICATE, truncate(content, 4000)));
	}

	private SSLContext trustAllContext() {
		try {
			SSLContext context = SSLContext.getInstance("TLS");
			context.init(null, new TrustManager[] { new TrustAllManager() }, null);
			return context;
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Не удалось создать TLS-контекст", exception);
		}
	}

	private String truncate(String value, int limit) {
		return value.length() <= limit ? value : value.substring(0, limit);
	}

	/**
	 * Данные сертификата, извлечённые из TLS-сессии.
	 */
	record CertificateInfo(
			String subject,
			String issuer,
			Instant notBefore,
			Instant notAfter,
			String protocol,
			List<String> alternativeNames,
			boolean selfSigned) {
	}

	private record SessionInfo(String protocol, X509Certificate certificate) {
	}

	private static final class TrustAllManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) {
			// Доверяем любому клиенту: используется только для чтения сертификата сервера.
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) {
			// Доверяем любому серверу: валидность цепочки проверяется отдельным соединением.
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}

	}

}
