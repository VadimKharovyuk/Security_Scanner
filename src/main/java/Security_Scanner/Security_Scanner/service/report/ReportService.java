package Security_Scanner.Security_Scanner.service.report;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.asset.AssetResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.report.ReportFindingGroup;
import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.dto.scan.ScanResponse;
import Security_Scanner.Security_Scanner.dto.scan.ScanTaskResponse;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.service.asset.AssetService;
import Security_Scanner.Security_Scanner.service.finding.FindingService;
import Security_Scanner.Security_Scanner.service.project.ProjectService;
import Security_Scanner.Security_Scanner.service.scan.ScanOrchestrator;
import lombok.RequiredArgsConstructor;

/**
 * Собирает отчёт по сканированию из уже сохранённых данных. Сетевых запросов не выполняет.
 */
@Service
@RequiredArgsConstructor
public class ReportService {

	static final String PASSIVE_ONLY_LIMITATION =
			"Выполнены только пассивные проверки: уязвимости не подтверждались атакующими запросами.";

	static final String NO_CRAWL_LIMITATION =
			"OWASP ZAP не запускался: проверен только адрес актива, остальные страницы не обходились.";

	static final String NOT_FINISHED_LIMITATION =
			"Сканирование ещё не завершено: отчёт неполный.";

	private static final Set<ScanStatus> FINISHED_STATUSES = Set.of(
			ScanStatus.COMPLETED,
			ScanStatus.PARTIALLY_COMPLETED,
			ScanStatus.FAILED,
			ScanStatus.CANCELLED);

	private final ScanOrchestrator scanOrchestrator;
	private final AssetService assetService;
	private final ProjectService projectService;
	private final FindingService findingService;

	@Transactional(readOnly = true)
	public ScanReport build(Long scanId) {
		ScanResponse scan = scanOrchestrator.findById(scanId);
		AssetResponse asset = assetService.findById(scan.assetId());

		return new ScanReport(
				Instant.now(),
				scan.id(),
				projectService.findById(asset.projectId()).name(),
				asset.id(),
				asset.name(),
				asset.baseUrl(),
				asset.ownershipStatus(),
				scan.status(),
				scan.status() == ScanStatus.COMPLETED,
				scan.errorMessage(),
				scan.startedAt(),
				scan.finishedAt(),
				limitations(scan),
				findingService.summarize(scanId),
				group(findingService.findByScan(scanId)),
				scan.tasks());
	}

	private List<String> limitations(ScanResponse scan) {
		List<String> limitations = new ArrayList<>();

		if (!FINISHED_STATUSES.contains(scan.status())) {
			limitations.add(NOT_FINISHED_LIMITATION);
		}

		for (ScanTaskResponse task : scan.tasks()) {
			if (task.status() == ScanTaskStatus.FAILED) {
				limitations.add("Сканер " + task.scannerType() + " завершился ошибкой: " + task.errorMessage());
			}
			else if (task.status() == ScanTaskStatus.SKIPPED || task.status() == ScanTaskStatus.CANCELLED) {
				limitations.add("Сканер " + task.scannerType() + " не выполнялся.");
			}
		}

		if (scan.tasks().stream().noneMatch(task -> task.scannerType() == ScannerType.OWASP_ZAP)) {
			limitations.add(NO_CRAWL_LIMITATION);
		}

		limitations.add(PASSIVE_ONLY_LIMITATION);

		return limitations;
	}

	private List<ReportFindingGroup> group(List<ScanFindingResponse> findings) {
		Map<String, List<ScanFindingResponse>> byCode = new LinkedHashMap<>();

		for (ScanFindingResponse finding : findings) {
			if (finding.status() != FindingStatus.FALSE_POSITIVE) {
				byCode.computeIfAbsent(finding.code(), code -> new ArrayList<>()).add(finding);
			}
		}

		return byCode.values().stream()
				.map(this::toGroup)
				.sorted(Comparator.comparing(ReportFindingGroup::severity)
						.thenComparing(ReportFindingGroup::code))
				.toList();
	}

	private ReportFindingGroup toGroup(List<ScanFindingResponse> occurrences) {
		ScanFindingResponse first = occurrences.get(0);

		// Порядок значений Severity идёт от CRITICAL к INFO, поэтому наибольшая критичность — минимальная.
		Severity severity = occurrences.stream()
				.map(ScanFindingResponse::severity)
				.min(Comparator.naturalOrder())
				.orElseThrow();

		return new ReportFindingGroup(
				first.code(),
				first.title(),
				first.description(),
				first.category(),
				severity,
				first.recommendation(),
				first.reference(),
				occurrences.stream()
						.sorted(Comparator.comparing(ScanFindingResponse::url))
						.toList());
	}

}
