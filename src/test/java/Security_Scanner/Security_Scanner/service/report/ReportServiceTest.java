package Security_Scanner.Security_Scanner.service.report;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.project.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.report.ReportFindingGroup;
import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.EvidenceType;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanTask;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.repository.ScanTaskRepository;
import Security_Scanner.Security_Scanner.service.asset.AssetService;
import Security_Scanner.Security_Scanner.service.finding.FindingService;
import Security_Scanner.Security_Scanner.service.project.ProjectService;
import Security_Scanner.Security_Scanner.service.scanner.EvidenceDraft;
import Security_Scanner.Security_Scanner.service.scanner.FindingDefinition;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;

@SpringBootTest(properties = {
		"security-scanner.scope.allowed-hosts=8.8.8.8",
		"security-scanner.recovery.enabled=false"
})
@Transactional
class ReportServiceTest {

	private static final String BASE = "https://8.8.8.8/";

	@Autowired
	private ReportService reportService;

	@Autowired
	private FindingService findingService;

	@Autowired
	private ProjectService projectService;

	@Autowired
	private AssetService assetService;

	@Autowired
	private ScanRepository scanRepository;

	@Autowired
	private ScanTaskRepository scanTaskRepository;

	@Autowired
	private WebApplicationContext webContext;

	private MockMvc mockMvc;

	private Scan scan;

	@BeforeEach
	void setUp() {
		mockMvc = MockMvcBuilders.webAppContextSetup(webContext).build();

		ProjectRequest projectRequest = new ProjectRequest();
		projectRequest.setName("Проект отчёта");
		Long projectId = projectService.create(projectRequest).id();

		AssetRequest assetRequest = new AssetRequest();
		assetRequest.setProjectId(projectId);
		assetRequest.setName("Актив отчёта");
		assetRequest.setBaseUrl("https://8.8.8.8");

		scan = new Scan();
		scan.setAsset(assetService.getEntity(assetService.create(assetRequest).id()));
		scan.setStatus(ScanStatus.COMPLETED);
		scan = scanRepository.save(scan);
	}

	@Test
	void groupsFindingsByRuleAndSortsBySeverity() {
		findingService.record(scan, List.of(
				draft("TEST_REPORT_LOW", Severity.LOW, "b"),
				draft("TEST_REPORT_LOW", Severity.LOW, "a"),
				draft("TEST_REPORT_HIGH", Severity.HIGH, "a")));

		ScanReport report = reportService.build(scan.getId());

		assertEquals(List.of("TEST_REPORT_HIGH", "TEST_REPORT_LOW"),
				report.findings().stream().map(ReportFindingGroup::code).toList());

		ReportFindingGroup low = report.findings().get(1);
		assertEquals(List.of(BASE + "a", BASE + "b"),
				low.occurrences().stream().map(occurrence -> occurrence.url()).toList());
		assertEquals(3, report.summary().total());
	}

	@Test
	void usesHighestSeverityInGroup() {
		findingService.record(scan, List.of(
				draft("TEST_REPORT_MIXED", Severity.LOW, "a"),
				draft("TEST_REPORT_MIXED", Severity.HIGH, "b")));

		assertEquals(Severity.HIGH, reportService.build(scan.getId()).findings().get(0).severity());
	}

	@Test
	void excludesFalsePositivesFromGroups() {
		findingService.record(scan, List.of(draft("TEST_REPORT_FP", Severity.HIGH, "a")));
		Long id = findingService.findByScan(scan.getId()).get(0).id();
		findingService.markFalsePositive(id);

		ScanReport report = reportService.build(scan.getId());

		assertTrue(report.findings().isEmpty());
		assertEquals(1, report.summary().total());
		assertEquals(0, report.summary().bySeverity().get(Severity.HIGH));
	}

	@Test
	void reportsWhatWasNotChecked() {
		task(ScannerType.HTTP, ScanTaskStatus.COMPLETED, null);
		task(ScannerType.TLS, ScanTaskStatus.FAILED, "Нет соединения");
		task(ScannerType.STUB, ScanTaskStatus.SKIPPED, null);

		List<String> limitations = reportService.build(scan.getId()).limitations();

		assertTrue(limitations.contains("Сканер TLS завершился ошибкой: Нет соединения"));
		assertTrue(limitations.contains("Сканер STUB не выполнялся."));
		assertTrue(limitations.contains(ReportService.NO_CRAWL_LIMITATION));
		assertTrue(limitations.contains(ReportService.PASSIVE_ONLY_LIMITATION));
	}

	@Test
	void doesNotClaimMissingCrawlWhenZapRan() {
		task(ScannerType.OWASP_ZAP, ScanTaskStatus.COMPLETED, null);

		assertFalse(reportService.build(scan.getId()).limitations().contains(ReportService.NO_CRAWL_LIMITATION));
	}

	@Test
	void marksUnfinishedScanAsIncomplete() {
		scan.setStatus(ScanStatus.RUNNING);

		ScanReport report = reportService.build(scan.getId());

		assertFalse(report.complete());
		assertTrue(report.limitations().contains(ReportService.NOT_FINISHED_LIMITATION));
	}

	@Test
	void partiallyCompletedScanIsNotComplete() {
		scan.setStatus(ScanStatus.PARTIALLY_COMPLETED);

		assertFalse(reportService.build(scan.getId()).complete());
	}

	@Test
	void rejectsUnknownScan() {
		assertThrows(ResourceNotFoundException.class, () -> reportService.build(-1L));
	}

	@Test
	void rendersHtmlAndEscapesContentFromScannedSite() throws Exception {
		findingService.record(scan, List.of(draft("TEST_REPORT_XSS", Severity.MEDIUM, "a")));

		mockMvc.perform(get("/scans/{id}/report", scan.getId()))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Отчёт по сканированию #" + scan.getId())))
				.andExpect(content().string(containsString("TEST_REPORT_XSS")))
				.andExpect(content().string(containsString("&lt;script&gt;")))
				.andExpect(content().string(not(containsString("<script>"))));
	}

	@Test
	void rendersEmptyReport() throws Exception {
		mockMvc.perform(get("/scans/{id}/report", scan.getId()))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Находок нет.")));
	}

	@Test
	void returnsJson() throws Exception {
		findingService.record(scan, List.of(draft("TEST_REPORT_JSON", Severity.HIGH, "a")));

		mockMvc.perform(get("/api/reports/{id}", scan.getId()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.scanId").value(scan.getId()))
				.andExpect(jsonPath("$.complete").value(true))
				.andExpect(jsonPath("$.summary.bySeverity.HIGH").value(1))
				.andExpect(jsonPath("$.findings[0].code").value("TEST_REPORT_JSON"))
				.andExpect(jsonPath("$.findings[0].occurrences[0].evidence[0].responseSnippet")
						.value(containsString("<script>")));
	}

	@Test
	void returnsNotFoundForUnknownScan() throws Exception {
		mockMvc.perform(get("/scans/{id}/report", -1L)).andExpect(status().isNotFound());
		mockMvc.perform(get("/api/reports/{id}", -1L)).andExpect(status().isNotFound());
	}

	private void task(ScannerType type, ScanTaskStatus status, String error) {
		ScanTask task = new ScanTask();
		task.setScan(scan);
		task.setScannerType(type);
		task.setStatus(status);
		task.setErrorMessage(error);
		scanTaskRepository.save(task);
	}

	private FindingDraft draft(String code, Severity severity, String path) {
		FindingDefinition definition = new FindingDefinition(
				code, "Правило " + code, "Описание", FindingCategory.CONFIGURATION,
				severity, Confidence.MEDIUM, "Исправить", "https://example.com");
		return FindingDraft.of(definition, BASE + path, new EvidenceDraft(
				EvidenceType.TEXT, "Доказательство", "GET " + BASE + path, "<script>alert(1)</script>"));
	}

}
