package Security_Scanner.Security_Scanner.service.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.IntFunction;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.ObjectProvider;

import com.sun.net.httpserver.HttpServer;

import Security_Scanner.Security_Scanner.config.OpenRouterConfig;
import Security_Scanner.Security_Scanner.config.OpenRouterProperties;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingSummary;
import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.enums.AiTaskType;
import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.AiUnavailableException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.service.finding.FindingService;
import Security_Scanner.Security_Scanner.service.report.ReportService;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Проверяет настоящий клиент Spring AI против локальной имитации API OpenRouter.
 */
class ScanAnalysisServiceTest {

	private static final Long SCAN_ID = 1L;

	private static final String API_KEY = "test-key";

	private final JsonMapper mapper = JsonMapper.builder().build();

	private final ReportService reportService = mock(ReportService.class);
	private final FindingService findingService = mock(FindingService.class);

	private final List<JsonNode> requests = new CopyOnWriteArrayList<>();
	private final List<String> paths = new CopyOnWriteArrayList<>();
	private final List<String> authorizations = new CopyOnWriteArrayList<>();

	private HttpServer server;
	private IntFunction<String> responses;
	private ScanAnalysisService service;

	@BeforeEach
	void setUp() throws IOException {
		server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		server.createContext("/", exchange -> {
			requests.add(mapper.readTree(exchange.getRequestBody().readAllBytes()));
			paths.add(exchange.getRequestURI().getPath());
			authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));

			byte[] body = responses.apply(requests.size()).getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, body.length);
			exchange.getResponseBody().write(body);
			exchange.close();
		});
		server.start();

		OpenRouterProperties properties = new OpenRouterProperties();
		properties.setApiKey(API_KEY);
		properties.setBaseUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1");
		properties.setModel("test/default-model");
		properties.setTemperature(0.3);
		properties.setMaxTokens(8192);

		OpenRouterProperties.TaskSettings analysis = new OpenRouterProperties.TaskSettings();
		analysis.setTemperature(0.2);
		properties.getTasks().put(AiTaskType.FINDING_ANALYSIS, analysis);

		service = service(new OpenRouterConfig().openRouterChatModel(properties), properties);

		when(reportService.build(SCAN_ID)).thenReturn(report());
		when(findingService.search(SCAN_ID, Severity.HIGH, null)).thenReturn(List.of(finding(5L, SCAN_ID)));
		when(findingService.findById(9L)).thenReturn(finding(9L, 2L));
	}

	@AfterEach
	void tearDown() {
		server.stop(0);
	}

	@Test
	void sendsConfiguredRequestToOpenRouterPath() {
		responses = attempt -> answer("Готово");

		assertEquals("Готово", service.analyze(SCAN_ID));

		assertEquals("/api/v1/chat/completions", paths.get(0));
		assertEquals("Bearer " + API_KEY, authorizations.get(0));

		JsonNode request = requests.get(0);
		assertEquals("test/default-model", request.path("model").asString());
		assertEquals(0.2, request.path("temperature").asDouble());
		assertEquals(8192, request.path("max_tokens").asInt());
		assertEquals("deny", request.path("provider").path("data_collection").asString());
	}

	@Test
	void offersOnlyReadTools() {
		responses = attempt -> answer("Готово");

		service.analyze(SCAN_ID);

		List<String> names = new ArrayList<>();
		requests.get(0).path("tools").forEach(tool -> names.add(tool.path("function").path("name").asString()));

		assertEquals(3, names.size());
		assertTrue(names.containsAll(List.of("getScanOverview", "searchFindings", "getFinding")));
	}

	@Test
	void runsToolsAndSendsResultsBackToModel() {
		responses = attempt -> switch (attempt) {
			case 1 -> toolCall("call_1", "getScanOverview", "{}");
			case 2 -> toolCall("call_2", "searchFindings", "{\"severity\":\"HIGH\"}");
			default -> answer("Итог анализа");
		};

		assertEquals("Итог анализа", service.analyze(SCAN_ID));
		assertEquals(3, requests.size());

		String sent = requests.get(2).path("messages").toString();
		assertTrue(sent.contains("https://example.com"), sent);
		assertTrue(sent.contains("CODE"), sent);
		verify(findingService).search(SCAN_ID, Severity.HIGH, null);
	}

	@Test
	void reportsForeignFindingToModelWithoutItsContent() {
		responses = attempt -> attempt == 1
				? toolCall("call_1", "getFinding", "{\"findingId\":9}")
				: answer("Находка недоступна");

		assertEquals("Находка недоступна", service.analyze(SCAN_ID));

		String sent = requests.get(1).path("messages").toString();
		assertFalse(sent.contains("Secret of other scan"), sent);
		assertTrue(sent.contains("Находка не найдена"), sent);
	}

	@Test
	void stopsEndlessToolCalls() {
		responses = attempt -> toolCall("call_" + attempt, "getScanOverview", "{}");

		assertThrows(AiUnavailableException.class, () -> service.analyze(SCAN_ID));

		assertTrue(requests.size() <= 11, "Запросов к модели: " + requests.size());
	}

	@Test
	void limitAppliesToEachAnalysisSeparately() {
		responses = attempt -> attempt % 9 == 0
				? answer("Готово")
				: toolCall("call_" + attempt, "getScanOverview", "{}");

		assertEquals("Готово", service.analyze(SCAN_ID));
		assertEquals("Готово", service.analyze(SCAN_ID));
		assertEquals(18, requests.size());
	}

	@Test
	void marksTruncatedAnswer() {
		responses = attempt -> completion(Map.of("role", "assistant", "content", "Начало"), "length");

		assertEquals("Начало" + ScanAnalysisService.TRUNCATED_NOTICE, service.analyze(SCAN_ID));
	}

	@Test
	void reportsEmptyAnswer() {
		responses = attempt -> answer("");

		assertThrows(AiUnavailableException.class, () -> service.analyze(SCAN_ID));
	}

	@Test
	void failsWithoutKeyAndWithoutCallingModel() {
		ScanAnalysisService withoutModel = service(null, new OpenRouterProperties());

		AiUnavailableException exception =
				assertThrows(AiUnavailableException.class, () -> withoutModel.analyze(SCAN_ID));

		assertTrue(exception.getMessage().contains("OPENROUTER_API_KEY"));
		assertTrue(requests.isEmpty());
	}

	@Test
	void unknownScanDoesNotCallModel() {
		when(reportService.build(99L)).thenThrow(new ResourceNotFoundException("Нет"));

		assertThrows(ResourceNotFoundException.class, () -> service.analyze(99L));

		assertTrue(requests.isEmpty());
		verify(findingService, never()).search(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	private ScanAnalysisService service(ChatModel model, OpenRouterProperties properties) {
		ObjectProvider<ChatModel> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(model);
		return new ScanAnalysisService(provider, new AiModelRouter(properties), reportService, findingService);
	}

	private String answer(String text) {
		return completion(Map.of("role", "assistant", "content", text), "stop");
	}

	private String toolCall(String id, String name, String arguments) {
		return completion(Map.of(
				"role", "assistant",
				"content", "",
				"tool_calls", List.of(Map.of(
						"id", id,
						"type", "function",
						"function", Map.of("name", name, "arguments", arguments)))),
				"tool_calls");
	}

	private String completion(Map<String, Object> message, String finishReason) {
		return mapper.writeValueAsString(Map.of(
				"id", "gen-1",
				"object", "chat.completion",
				"created", 1,
				"model", "test/default-model",
				"choices", List.of(Map.of(
						"index", 0,
						"finish_reason", finishReason,
						"logprobs", Map.of("content", List.of(), "refusal", List.of()),
						"message", new java.util.HashMap<>(withRefusal(message))))));
	}

	private Map<String, Object> withRefusal(Map<String, Object> message) {
		Map<String, Object> result = new java.util.HashMap<>(message);
		result.put("refusal", "");
		return result;
	}

	private ScanReport report() {
		return new ScanReport(Instant.EPOCH, SCAN_ID, "Проект", 2L, "Актив", "https://example.com",
				null, ScanStatus.COMPLETED, true, null, null, null,
				List.of("Выполнены только пассивные проверки."),
				new ScanFindingSummary(SCAN_ID, 0, Map.of(), Map.of()),
				List.of(), List.of());
	}

	private ScanFindingResponse finding(Long id, Long scanId) {
		return new ScanFindingResponse(id, scanId, 3L, "CODE", "Secret of other scan", "Description",
				FindingCategory.CONFIGURATION, FindingStatus.OPEN, Severity.HIGH, Confidence.LOW,
				"Fix", "", "https://example.com/", Instant.EPOCH, List.of());
	}

}
