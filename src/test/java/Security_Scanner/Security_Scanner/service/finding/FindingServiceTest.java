package Security_Scanner.Security_Scanner.service.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingSummary;
import Security_Scanner.Security_Scanner.dto.project.ProjectRequest;
import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.EvidenceType;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanFinding;
import Security_Scanner.Security_Scanner.repository.ScanFindingRepository;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.service.asset.AssetService;
import Security_Scanner.Security_Scanner.service.project.ProjectService;
import Security_Scanner.Security_Scanner.service.scanner.EvidenceDraft;
import Security_Scanner.Security_Scanner.service.scanner.FindingDefinition;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;

@SpringBootTest(properties = {
		"security-scanner.scope.allowed-hosts=8.8.8.8",
		"security-scanner.recovery.enabled=false"
})
@Transactional
class FindingServiceTest {

	private static final long MISSING_SCAN_ID = -1L;

	@Autowired
	private FindingService findingService;

	@Autowired
	private ProjectService projectService;

	@Autowired
	private AssetService assetService;

	@Autowired
	private ScanRepository scanRepository;

	@Autowired
	private ScanFindingRepository scanFindingRepository;

	private Scan scan;

	@BeforeEach
	void setUp() {
		ProjectRequest projectRequest = new ProjectRequest();
		projectRequest.setName("Находки");
		Long projectId = projectService.create(projectRequest).id();

		AssetRequest assetRequest = new AssetRequest();
		assetRequest.setProjectId(projectId);
		assetRequest.setName("Актив");
		assetRequest.setBaseUrl("https://8.8.8.8");

		scan = new Scan();
		scan.setAsset(assetService.getEntity(assetService.create(assetRequest).id()));
		scan.setStatus(ScanStatus.RUNNING);
		scan = scanRepository.save(scan);

		findingService.record(scan, List.of(
				draft("TEST_FINDING_HIGH", Severity.HIGH),
				draft("TEST_FINDING_LOW_A", Severity.LOW),
				draft("TEST_FINDING_LOW_B", Severity.LOW)));
	}

	@Test
	void savesFindingWithRuleCreatedOnTheFly() {
		List<ScanFindingResponse> findings = findingService.search(scan.getId(), Severity.HIGH, null);

		assertEquals(1, findings.size());
		assertEquals("TEST_FINDING_HIGH", findings.get(0).code());
		assertEquals(1, findings.get(0).evidence().size());
	}

	@Test
	void filtersBySeverityAndStatus() {
		Long lowId = findingService.search(scan.getId(), Severity.LOW, null).get(0).id();
		findingService.markFalsePositive(lowId);

		assertEquals(3, findingService.search(scan.getId(), null, null).size());
		assertEquals(2, findingService.search(scan.getId(), Severity.LOW, null).size());
		assertEquals(2, findingService.search(scan.getId(), null, FindingStatus.OPEN).size());
		assertEquals(1, findingService.search(scan.getId(), Severity.LOW, FindingStatus.OPEN).size());
		assertEquals(0, findingService.search(scan.getId(), Severity.INFO, null).size());
	}

	@Test
	void summarizesAndExcludesFalsePositivesFromSeverity() {
		Long lowId = findingService.search(scan.getId(), Severity.LOW, null).get(0).id();
		findingService.markFalsePositive(lowId);

		ScanFindingSummary summary = findingService.summarize(scan.getId());

		assertEquals(3, summary.total());
		assertEquals(1, summary.bySeverity().get(Severity.HIGH));
		assertEquals(1, summary.bySeverity().get(Severity.LOW));
		assertEquals(0, summary.bySeverity().get(Severity.CRITICAL));
		assertEquals(2, summary.byStatus().get(FindingStatus.OPEN));
		assertEquals(1, summary.byStatus().get(FindingStatus.FALSE_POSITIVE));
	}

	@Test
	void marksFalsePositiveAndReopens() {
		Long id = findingService.search(scan.getId(), Severity.HIGH, null).get(0).id();

		assertEquals(FindingStatus.FALSE_POSITIVE, findingService.markFalsePositive(id).status());
		assertEquals(FindingStatus.OPEN, findingService.reopen(id).status());
	}

	@Test
	void rejectsInvalidTransitions() {
		Long id = findingService.search(scan.getId(), Severity.HIGH, null).get(0).id();

		assertThrows(ConflictException.class, () -> findingService.reopen(id));

		ScanFinding confirmed = scanFindingRepository.findById(id).orElseThrow();
		confirmed.setStatus(FindingStatus.CONFIRMED);

		assertThrows(ConflictException.class, () -> findingService.markFalsePositive(id));
		assertThrows(ConflictException.class, () -> findingService.reopen(id));
	}

	@Test
	void rejectsUnknownScan() {
		assertThrows(ResourceNotFoundException.class, () -> findingService.search(MISSING_SCAN_ID, null, null));
		assertThrows(ResourceNotFoundException.class, () -> findingService.summarize(MISSING_SCAN_ID));
	}

	private FindingDraft draft(String code, Severity severity) {
		FindingDefinition definition = new FindingDefinition(
				code, code, "Описание", FindingCategory.CONFIGURATION, severity, Confidence.MEDIUM, "Исправить", "");
		return FindingDraft.of(definition, "https://8.8.8.8/" + code, EvidenceDraft.of(EvidenceType.TEXT, "Доказательство"));
	}

}
