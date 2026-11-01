package Security_Scanner.Security_Scanner.service.ai;

import java.util.List;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingSummary;
import Security_Scanner.Security_Scanner.dto.report.ReportFindingGroup;
import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.service.finding.FindingService;
import Security_Scanner.Security_Scanner.service.report.ReportService;
import lombok.extern.slf4j.Slf4j;

/**
 * Инструменты модели только для чтения. Создаются на один запрос и привязаны к одному сканированию:
 * содержимое сайта может содержать prompt injection, поэтому модель не может изменить данные
 * или прочитать другие сканирования. Размер ответов ограничен, потому что он оплачивается.
 */
@Slf4j
class ScanReadTools {

	static final int MAX_FINDINGS = 50;

	static final int MAX_RULE_TEXT = 600;

	private final Long scanId;
	private final ReportService reportService;
	private final FindingService findingService;

	ScanReadTools(Long scanId, ReportService reportService, FindingService findingService) {
		this.scanId = scanId;
		this.reportService = reportService;
		this.findingService = findingService;
	}

	@Tool(description = "Обзор сканирования: актив, статус, ограничения проверки, сводка и все сработавшие правила "
			+ "с описанием, рекомендацией, числом адресов и ID примера находки. Вызывайте первым.")
	public ScanOverview getScanOverview() {
		log.info("AI-анализ сканирования {}: инструмент getScanOverview", scanId);

		ScanReport report = reportService.build(scanId);

		return new ScanOverview(
				report.assetUrl(),
				report.status(),
				report.complete(),
				report.limitations(),
				report.summary(),
				report.findings().stream().map(this::toRule).toList());
	}

	@Tool(description = "Список находок сканирования без доказательств, с необязательными фильтрами. "
			+ "Возвращает не больше 50 находок и общее число подходящих.")
	public FindingList searchFindings(
			@ToolParam(required = false, description = "Критичность") Severity severity,
			@ToolParam(required = false, description = "Статус") FindingStatus status) {

		log.info("AI-анализ сканирования {}: инструмент searchFindings, критичность {}, статус {}",
				scanId, severity, status);

		List<ScanFindingResponse> findings = findingService.search(scanId, severity, status);

		return new FindingList(
				findings.size(),
				findings.stream()
						.limit(MAX_FINDINGS)
						.map(finding -> new FindingBrief(
								finding.id(), finding.code(), finding.title(),
								finding.severity(), finding.confidence().name(), finding.status(), finding.url()))
						.toList());
	}

	@Tool(description = "Доказательства одной находки этого сканирования. Вызывайте только для самых важных правил, "
			+ "по одному примеру exampleFindingId: перебирать все находки не нужно.")
	public ScanFindingResponse getFinding(@ToolParam(description = "ID находки из searchFindings") Long findingId) {
		log.info("AI-анализ сканирования {}: инструмент getFinding, находка {}", scanId, findingId);

		ScanFindingResponse finding = findingService.findById(findingId);

		if (!scanId.equals(finding.scanId())) {
			throw new ResourceNotFoundException("Находка не найдена: " + findingId);
		}

		return finding;
	}

	private RuleBrief toRule(ReportFindingGroup group) {
		return new RuleBrief(
				group.code(),
				group.title(),
				truncate(group.description()),
				truncate(group.recommendation()),
				group.category(),
				group.severity(),
				group.occurrences().size(),
				group.occurrences().isEmpty() ? null : group.occurrences().get(0).id());
	}

	private static String truncate(String value) {
		if (value == null || value.length() <= MAX_RULE_TEXT) {
			return value;
		}
		return value.substring(0, MAX_RULE_TEXT) + "…";
	}

	record ScanOverview(
			String assetUrl,
			ScanStatus status,
			boolean complete,
			List<String> limitations,
			ScanFindingSummary summary,
			List<RuleBrief> rules) {
	}

	record RuleBrief(
			String code,
			String title,
			String description,
			String recommendation,
			FindingCategory category,
			Severity severity,
			int addresses,
			Long exampleFindingId) {
	}

	record FindingList(int total, List<FindingBrief> findings) {
	}

	record FindingBrief(
			Long id,
			String code,
			String title,
			Severity severity,
			String confidence,
			FindingStatus status,
			String url) {
	}

}
