package Security_Scanner.Security_Scanner.service.scanner.zap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import Security_Scanner.Security_Scanner.config.ZapProperties;
import Security_Scanner.Security_Scanner.exception.ScopeViolationException;
import Security_Scanner.Security_Scanner.service.asset.AssetScopeService;
import Security_Scanner.Security_Scanner.service.scanner.ScanContext;
import Security_Scanner.Security_Scanner.service.scanner.ScanResult;

class ZapScannerTest {

	private static final String URL = "https://example.com";

	private final AssetScopeService scope = mock(AssetScopeService.class);
	private final ZapClient zap = mock(ZapClient.class);
	private final ZapProperties properties = new ZapProperties();

	private ZapScanner scanner;

	@BeforeEach
	void setUp() throws Exception {
		properties.setApiKey("key");
		properties.setPollInterval(Duration.ofMillis(1));
		scanner = new ZapScanner(scope, zap, properties);

		when(scope.validateAndNormalize(URL)).thenReturn(URL);
		when(zap.startSpider(anyString(), anyString())).thenReturn("7");
		when(zap.spiderProgress("7")).thenReturn(100);
		when(zap.spiderResultCount("7")).thenReturn(3);
	}

	@Test
	void scopeRegexMatchesOnlyAssetHost() {
		Pattern scope = Pattern.compile(ZapScanner.scopeRegex(URI.create(URL)));

		assertTrue(scope.matcher("https://example.com").matches());
		assertTrue(scope.matcher("https://example.com/a/b?x=1").matches());
		assertTrue(scope.matcher("http://example.com:80/").matches());

		assertFalse(scope.matcher("https://example.com.evil.org/").matches());
		assertFalse(scope.matcher("https://evil.org/https://example.com/").matches());
		assertFalse(scope.matcher("https://sub.example.com/").matches());
		assertFalse(scope.matcher("https://exampleXcom/").matches());
		assertFalse(scope.matcher("https://example.com:8080/").matches());
		assertFalse(scope.matcher("https://example.com@evil.org/").matches());
	}

	@Test
	void scopeRegexRequiresCustomPort() {
		Pattern scope = Pattern.compile(ZapScanner.scopeRegex(URI.create("https://example.com:8443")));

		assertTrue(scope.matcher("https://example.com:8443/a").matches());
		assertFalse(scope.matcher("https://example.com/a").matches());
		assertFalse(scope.matcher("https://example.com:84430/a").matches());
	}

	@Test
	void runsPassiveScanAndReturnsFindings() throws Exception {
		when(zap.alerts(URL, 0, 500)).thenReturn(List.of(new ZapAlert("Rule", "1", "1", "Low", "Low",
				URL + "/a", "GET", "", "", "", "", "", "")));

		ScanResult result = scanner.execute(context(() -> false));

		assertTrue(result.success());
		assertEquals("Обойдено адресов: 3", result.message());
		assertEquals(1, result.findings().size());

		verify(zap).newSession();
		verify(zap).configureSpider(5, 5, 2);
		verify(zap).startSpider(URL, "scan-1");
	}

	@Test
	void reachesLocalTargetThroughDockerHostAndReportsAssetUrl() throws Exception {
		String local = "http://localhost:1018";
		String docker = "http://host.docker.internal:1018";
		when(scope.validateAndNormalize(local)).thenReturn(local);
		when(zap.alerts(docker, 0, 500)).thenReturn(List.of(new ZapAlert("Rule", "1", "1", "Low", "Low",
				docker + "/a?x=1", "GET", "", "", "", "", "", "")));

		ScanResult result = scanner.execute(new ScanContext(1L, 2L, 3L, local, Duration.ofSeconds(5), () -> false));

		assertTrue(result.success());
		assertEquals(1, result.findings().size());
		assertEquals(local + "/a", result.findings().get(0).url());
		verify(zap).startSpider(docker, "scan-1");
		verify(zap).createContext("scan-1", ZapScanner.scopeRegex(URI.create(docker)));
	}

	@Test
	void limitsSavedFindings() throws Exception {
		properties.setMaxFindings(1);
		when(zap.alerts(URL, 0, 500)).thenReturn(List.of(
				new ZapAlert("A", "1", "1", "Low", "Low", URL + "/a", "GET", "", "", "", "", "", ""),
				new ZapAlert("B", "2", "2", "High", "Low", URL + "/b", "GET", "", "", "", "", "", "")));

		ScanResult result = scanner.execute(context(() -> false));

		assertEquals(1, result.findings().size());
		assertEquals("ZAP_2", result.findings().get(0).definition().code());
		assertTrue(result.message().contains("сохранено 1 из 2"));
	}

	@Test
	void doesNotCallZapOutsideScope() throws Exception {
		when(scope.validateAndNormalize(URL)).thenThrow(new ScopeViolationException("Вне области"));

		ScanResult result = scanner.execute(context(() -> false));

		assertFalse(result.success());
		assertEquals("Вне области", result.message());
		verifyNoInteractions(zap);
	}

	@Test
	void requiresApiKey() {
		properties.setApiKey(" ");

		assertFalse(scanner.execute(context(() -> false)).success());
		verifyNoInteractions(zap);
	}

	@Test
	void stopsSpiderOnCancel() throws Exception {
		when(zap.spiderProgress("7")).thenReturn(10);
		BooleanSupplier cancel = new BooleanSupplier() {
			private int calls;

			@Override
			public boolean getAsBoolean() {
				return ++calls > 1;
			}
		};

		ScanResult result = scanner.execute(context(cancel));

		assertFalse(result.success());
		verify(zap).stopSpider("7");
		verify(zap, never()).alerts(any(), anyInt(), anyInt());
	}

	@Test
	void keepsResultsWhenSpiderTimesOut() throws Exception {
		when(zap.spiderProgress("7")).thenReturn(10);

		ScanResult result = scanner.execute(new ScanContext(1L, 2L, 3L, URL, Duration.ofMillis(50), () -> false));

		assertTrue(result.success());
		assertTrue(result.message().contains("таймауту"));
		verify(zap).stopSpider("7");
	}

	@Test
	void reportsUnavailableZap() throws Exception {
		org.mockito.Mockito.doThrow(new IOException("Connection refused")).when(zap).newSession();

		ScanResult result = scanner.execute(context(() -> false));

		assertFalse(result.success());
		assertTrue(result.message().contains("Connection refused"));
	}

	@Test
	void releasesSessionAfterFailure() throws Exception {
		org.mockito.Mockito.doThrow(new IOException("Connection refused")).when(zap).newSession();
		scanner.execute(context(() -> false));

		org.mockito.Mockito.doNothing().when(zap).newSession();
		when(zap.alerts(URL, 0, 500)).thenReturn(List.of());

		assertTrue(scanner.execute(context(() -> false)).success());
	}

	private ScanContext context(BooleanSupplier cancel) {
		return new ScanContext(1L, 2L, 3L, URL, Duration.ofSeconds(5), cancel);
	}

}
