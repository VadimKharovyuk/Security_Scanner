package Security_Scanner.Security_Scanner.service.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.ai.tool.annotation.Tool;

import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.report.ReportFindingGroup;
import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.service.finding.FindingService;
import Security_Scanner.Security_Scanner.service.report.ReportService;

class ScanReadToolsTest {

	private static final Long SCAN_ID = 1L;

	private final ReportService reportService = mock(ReportService.class);
	private final FindingService findingService = mock(FindingService.class);

	private final ScanReadTools tools = new ScanReadTools(SCAN_ID, reportService, findingService);

	@Test
	void exposesOnlyReadTools() {
		Set<String> names = Arrays.stream(ScanReadTools.class.getDeclaredMethods())
				.filter(method -> method.isAnnotationPresent(Tool.class))
				.map(Method::getName)
				.collect(Collectors.toSet());

		assertEquals(Set.of("getScanOverview", "searchFindings", "getFinding"), names);
	}

	@Test
	void limitsFindingListAndKeepsTotal() {
		when(findingService.search(SCAN_ID, Severity.LOW, null))
				.thenReturn(Collections.nCopies(ScanReadTools.MAX_FINDINGS + 5, finding(7L, SCAN_ID)));

		ScanReadTools.FindingList result = tools.searchFindings(Severity.LOW, null);

		assertEquals(ScanReadTools.MAX_FINDINGS + 5, result.total());
		assertEquals(ScanReadTools.MAX_FINDINGS, result.findings().size());
	}

	@Test
	void findingListExcludesEvidence() {
		when(findingService.search(SCAN_ID, null, FindingStatus.OPEN)).thenReturn(List.of(finding(7L, SCAN_ID)));

		ScanReadTools.FindingBrief brief = tools.searchFindings(null, FindingStatus.OPEN).findings().get(0);

		assertEquals(7L, brief.id());
		assertTrue(Arrays.stream(ScanReadTools.FindingBrief.class.getRecordComponents())
				.noneMatch(component -> component.getName().equals("evidence")));
	}

	@Test
	void returnsFindingOfBoundScan() {
		ScanFindingResponse finding = finding(7L, SCAN_ID);
		when(findingService.findById(7L)).thenReturn(finding);

		assertSame(finding, tools.getFinding(7L));
	}

	@Test
	void hidesFindingOfOtherScan() {
		when(findingService.findById(8L)).thenReturn(finding(8L, 2L));

		assertThrows(ResourceNotFoundException.class, () -> tools.getFinding(8L));
	}

	@Test
	void overviewDescribesRulesWithoutRequestingEachFinding() {
		ReportFindingGroup group = new ReportFindingGroup("CODE", "Title", "D".repeat(ScanReadTools.MAX_RULE_TEXT + 1),
				FindingCategory.CONFIGURATION, Severity.LOW, "Fix", "", List.of(finding(7L, SCAN_ID), finding(8L, SCAN_ID)));
		ScanReport report = mock(ScanReport.class);
		when(report.findings()).thenReturn(List.of(group));
		when(reportService.build(SCAN_ID)).thenReturn(report);

		ScanReadTools.RuleBrief rule = tools.getScanOverview().rules().get(0);

		assertEquals(ScanReadTools.MAX_RULE_TEXT + 1, rule.description().length());
		assertTrue(rule.description().endsWith("…"));
		assertEquals("Fix", rule.recommendation());
		assertEquals(2, rule.addresses());
		assertEquals(7L, rule.exampleFindingId());
	}

	private ScanFindingResponse finding(Long id, Long scanId) {
		return new ScanFindingResponse(id, scanId, 3L, "CODE", "Title", "Description",
				FindingCategory.CONFIGURATION, FindingStatus.OPEN, Severity.LOW, Confidence.LOW,
				"Fix", "", "https://example.com/", Instant.EPOCH, List.of());
	}

}
