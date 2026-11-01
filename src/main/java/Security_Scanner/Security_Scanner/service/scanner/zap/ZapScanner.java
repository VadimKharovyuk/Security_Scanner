package Security_Scanner.Security_Scanner.service.scanner.zap;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import Security_Scanner.Security_Scanner.config.ZapProperties;
import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.exception.ScopeViolationException;
import Security_Scanner.Security_Scanner.service.asset.AssetScopeService;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;
import Security_Scanner.Security_Scanner.service.scanner.ScanContext;
import Security_Scanner.Security_Scanner.service.scanner.ScanResult;
import Security_Scanner.Security_Scanner.service.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Пассивный анализ через OWASP ZAP: обход сайта в пределах актива и разбор полученных ответов.
 * Активное сканирование не выполняется: оно требует подтверждения владения, авторизации и аудита.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security-scanner.zap.enabled", havingValue = "true")
public class ZapScanner implements SecurityScanner {

	private static final int ALERTS_PAGE_SIZE = 500;

	private static final int MAX_ALERTS = 5000;

	private static final String LOCAL_HOST = "localhost";

	private final AssetScopeService assetScopeService;
	private final ZapClient zap;
	private final ZapProperties properties;

	/**
	 * Сессия ZAP одна на процесс, поэтому сканирования выполняются строго по очереди.
	 */
	private final ReentrantLock sessionLock = new ReentrantLock();

	private enum Outcome {
		FINISHED, TIMED_OUT, CANCELLED
	}

	@Override
	public ScannerType getType() {
		return ScannerType.OWASP_ZAP;
	}

	@Override
	public Duration getTimeout() {
		return properties.getTimeout();
	}

	@Override
	public ScanResult execute(ScanContext context) {
		Instant startedAt = Instant.now();

		if (!StringUtils.hasText(properties.getApiKey())) {
			return ScanResult.failure("Не задан ключ API ZAP (ZAP_API_KEY)", startedAt);
		}

		boolean locked = false;
		try {
			String url = assetScopeService.validateAndNormalize(context.baseUrl());
			Instant deadline = startedAt.plus(context.timeout());

			locked = acquireSession(context, deadline);
			if (!locked) {
				return ScanResult.failure("ZAP занят другим сканированием или сканирование отменено", startedAt);
			}

			// Повторная проверка области непосредственно перед обходом.
			assetScopeService.validateAndNormalize(url);

			return scan(url, context, deadline, startedAt);
		}
		catch (ScopeViolationException exception) {
			return ScanResult.failure(exception.getMessage(), startedAt);
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			return ScanResult.failure("Сканирование ZAP прервано", startedAt);
		}
		catch (IOException exception) {
			log.warn("Ошибка обращения к ZAP", exception);
			return ScanResult.failure("Ошибка обращения к ZAP: " + describe(exception), startedAt);
		}
		finally {
			if (locked) {
				sessionLock.unlock();
			}
		}
	}

	/**
	 * Строит регулярное выражение области ZAP: только хост и порт актива.
	 */
	static String scopeRegex(URI target) {
		String port = target.getPort() == -1 ? "(?::(?:80|443))?" : ":" + target.getPort();
		return "^https?://" + Pattern.quote(target.getHost()) + port + "(?:[/?#].*)?$";
	}

	private ScanResult scan(String url, ScanContext context, Instant deadline, Instant startedAt)
			throws IOException, InterruptedException {

		URI target = URI.create(url);
		URI zapTarget = reachableFromZap(target);
		String contextName = "scan-" + context.scanId();

		zap.newSession();
		zap.createContext(contextName, scopeRegex(zapTarget));
		zap.configureSpider(properties.getMaxDepth(), properties.getMaxSpiderMinutes(), properties.getSpiderThreads());

		String spiderId = zap.startSpider(zapTarget.toString(), contextName);

		Outcome spider = awaitSpider(spiderId, context, deadline);
		if (spider == Outcome.CANCELLED) {
			return ScanResult.failure("Сканирование ZAP отменено", startedAt);
		}

		Outcome passive = awaitPassiveScan(context, deadline);
		if (passive == Outcome.CANCELLED) {
			return ScanResult.failure("Сканирование ZAP отменено", startedAt);
		}

		List<ZapAlert> alerts = withAssetHost(loadAlerts(zapTarget.toString()), zapTarget, target);
		List<FindingDraft> found = ZapAlertMapper.toFindings(alerts, target);
		List<FindingDraft> findings = found.stream().limit(properties.getMaxFindings()).toList();

		return ScanResult.success(
				message(zap.spiderResultCount(spiderId), spider, passive, found.size(), findings.size()),
				startedAt,
				findings);
	}

	private URI reachableFromZap(URI target) {
		if (!LOCAL_HOST.equalsIgnoreCase(target.getHost())) {
			return target;
		}
		return withHost(target, properties.getLocalTargetHost());
	}

	private static URI withHost(URI uri, String host) {
		return UriComponentsBuilder.fromUri(uri).host(host).build(true).toUri();
	}

	/**
	 * Возвращает находкам адрес актива вместо адреса, по которому к нему обращался ZAP.
	 */
	static List<ZapAlert> withAssetHost(List<ZapAlert> alerts, URI zapTarget, URI target) {
		if (zapTarget.equals(target)) {
			return alerts;
		}

		String zapOrigin = zapTarget.getScheme() + "://" + zapTarget.getRawAuthority();
		String origin = target.getScheme() + "://" + target.getRawAuthority();

		return alerts.stream()
				.map(alert -> alert.url() != null && alert.url().startsWith(zapOrigin)
						? alert.withUrl(origin + alert.url().substring(zapOrigin.length()))
						: alert)
				.toList();
	}

	private boolean acquireSession(ScanContext context, Instant deadline) throws InterruptedException {
		while (Instant.now().isBefore(deadline)) {
			if (context.cancelRequested().getAsBoolean()) {
				return false;
			}
			if (sessionLock.tryLock(properties.getPollInterval().toMillis(), TimeUnit.MILLISECONDS)) {
				return true;
			}
		}
		return false;
	}

	private Outcome awaitSpider(String spiderId, ScanContext context, Instant deadline)
			throws IOException, InterruptedException {

		while (zap.spiderProgress(spiderId) < 100) {
			if (context.cancelRequested().getAsBoolean()) {
				zap.stopSpider(spiderId);
				return Outcome.CANCELLED;
			}
			if (!Instant.now().isBefore(deadline)) {
				zap.stopSpider(spiderId);
				return Outcome.TIMED_OUT;
			}
			Thread.sleep(properties.getPollInterval());
		}
		return Outcome.FINISHED;
	}

	private Outcome awaitPassiveScan(ScanContext context, Instant deadline)
			throws IOException, InterruptedException {

		while (zap.passiveRecordsToScan() > 0) {
			if (context.cancelRequested().getAsBoolean()) {
				return Outcome.CANCELLED;
			}
			if (!Instant.now().isBefore(deadline)) {
				return Outcome.TIMED_OUT;
			}
			Thread.sleep(properties.getPollInterval());
		}
		return Outcome.FINISHED;
	}

	private List<ZapAlert> loadAlerts(String url) throws IOException, InterruptedException {
		List<ZapAlert> alerts = new ArrayList<>();

		while (alerts.size() < MAX_ALERTS) {
			List<ZapAlert> page = zap.alerts(url, alerts.size(), ALERTS_PAGE_SIZE);
			alerts.addAll(page);
			if (page.size() < ALERTS_PAGE_SIZE) {
				break;
			}
		}

		return alerts;
	}

	private String message(int pages, Outcome spider, Outcome passive, int found, int saved) {
		String message = "Обойдено адресов: " + pages;

		if (spider == Outcome.TIMED_OUT) {
			message += ", обход остановлен по таймауту";
		}
		if (passive == Outcome.TIMED_OUT) {
			message += ", анализ ответов остановлен по таймауту";
		}
		if (saved < found) {
			message += ", сохранено " + saved + " из " + found + " находок";
		}

		return message;
	}

	private String describe(IOException exception) {
		return exception.getMessage() != null ? exception.getMessage() : exception.getClass().getSimpleName();
	}

}
