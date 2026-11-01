package Security_Scanner.Security_Scanner.service.scanner.zap;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.config.ZapProperties;
import lombok.RequiredArgsConstructor;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Клиент REST API OWASP ZAP. Ключ передаётся в заголовке, чтобы не попадать в URL и логи.
 * Вызовов активного сканирования здесь нет намеренно.
 */
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security-scanner.zap.enabled", havingValue = "true")
class ZapClient {

	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

	private static final String API_KEY_HEADER = "X-ZAP-API-Key";

	private final ZapProperties properties;

	private final HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(Duration.ofSeconds(5))
			.followRedirects(HttpClient.Redirect.NEVER)
			.build();

	private final JsonMapper mapper = JsonMapper.builder().build();

	void newSession() throws IOException, InterruptedException {
		call("core/action/newSession", Map.of("overwrite", "true"));
	}

	void createContext(String name, String includeRegex) throws IOException, InterruptedException {
		call("context/action/newContext", Map.of("contextName", name));
		call("context/action/includeInContext", Map.of("contextName", name, "regex", includeRegex));
	}

	/**
	 * Формы отключены: spider иначе отправляет POST-запросы и может создать данные на сайте.
	 */
	void configureSpider(int maxDepth, int maxMinutes, int threads) throws IOException, InterruptedException {
		call("spider/action/setOptionMaxDepth", Map.of("Integer", String.valueOf(maxDepth)));
		call("spider/action/setOptionMaxDuration", Map.of("Integer", String.valueOf(maxMinutes)));
		call("spider/action/setOptionThreadCount", Map.of("Integer", String.valueOf(threads)));
		call("spider/action/setOptionProcessForm", Map.of("Boolean", "false"));
		call("spider/action/setOptionPostForm", Map.of("Boolean", "false"));
	}

	String startSpider(String url, String contextName) throws IOException, InterruptedException {
		return text(call("spider/action/scan", Map.of("url", url, "contextName", contextName)), "scan");
	}

	int spiderProgress(String scanId) throws IOException, InterruptedException {
		return number(call("spider/view/status", Map.of("scanId", scanId)), "status");
	}

	void stopSpider(String scanId) throws IOException, InterruptedException {
		call("spider/action/stop", Map.of("scanId", scanId));
	}

	int spiderResultCount(String scanId) throws IOException, InterruptedException {
		return call("spider/view/results", Map.of("scanId", scanId)).path("results").size();
	}

	int passiveRecordsToScan() throws IOException, InterruptedException {
		return number(call("pscan/view/recordsToScan", Map.of()), "recordsToScan");
	}

	List<ZapAlert> alerts(String baseUrl, int start, int count) throws IOException, InterruptedException {
		Map<String, String> params = new LinkedHashMap<>();
		params.put("baseurl", baseUrl);
		params.put("start", String.valueOf(start));
		params.put("count", String.valueOf(count));

		List<ZapAlert> alerts = new ArrayList<>();
		for (JsonNode node : call("alert/view/alerts", params).path("alerts")) {
			alerts.add(mapper.treeToValue(node, ZapAlert.class));
		}
		return alerts;
	}

	private JsonNode call(String path, Map<String, String> params) throws IOException, InterruptedException {
		String query = params.entrySet().stream()
				.map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
				.collect(Collectors.joining("&"));

		HttpRequest request = HttpRequest.newBuilder(URI.create(properties.getUrl() + "/JSON/" + path + "/?" + query))
				.header(API_KEY_HEADER, properties.getApiKey())
				.timeout(REQUEST_TIMEOUT)
				.GET()
				.build();

		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		try {
			JsonNode body = mapper.readTree(response.body());
			if (response.statusCode() != 200) {
				throw new IOException("ZAP вернул ошибку " + response.statusCode() + " для " + path
						+ ": " + body.path("message").asString(""));
			}
			return body;
		}
		catch (JacksonException exception) {
			throw new IOException("Некорректный ответ ZAP для " + path, exception);
		}
	}

	private String text(JsonNode node, String field) throws IOException {
		String value = node.path(field).asString("");
		if (value.isEmpty()) {
			throw new IOException("В ответе ZAP нет поля " + field);
		}
		return value;
	}

	private int number(JsonNode node, String field) throws IOException {
		try {
			return Integer.parseInt(text(node, field));
		}
		catch (NumberFormatException exception) {
			throw new IOException("Некорректное значение поля " + field + " в ответе ZAP", exception);
		}
	}

	private String encode(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

}
