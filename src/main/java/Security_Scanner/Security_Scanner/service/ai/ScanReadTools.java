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

/**
 * Инструменты модели только для чтения. Создаются на один запрос и привязаны к одному сканированию:
 * содержимое сайта может содержать prompt injection, поэтому модель не может изменить данные
 * или прочитать другие сканирования. Размер ответов ограничен, потому что он оплачивается.
 */
class ScanReadTools {

	static final int MAX_FINDINGS = 50;

	private final Long scanId;
	private final ReportService reportService;
	private final FindingService findingService;

	ScanReadTools(Long scanId, ReportService reportService, FindingService findingService) {
		this.scanId = scanId;
		this.reportService = reportService;
		this.findingService = findingService;
	}

	@Tool(description = "Обзор сканирования: актив, статус, ограничения проверки, сводка и правила с числом адресов. "
			+ "Вызывайте первым.")
	public ScanOverview getScanOverview() {
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

	@Tool(description = "Полные данные одной находки этого сканирования: описание, рекомендация и доказательства.")
	public ScanFindingResponse getFinding(@ToolParam(description = "ID находки из searchFindings") Long findingId) {
		ScanFindingResponse finding = findingService.findById(findingId);

		if (!scanId.equals(finding.scanId())) {
			throw new ResourceNotFoundException("Находка не найдена: " + findingId);
		}

		return finding;
	}

	private RuleBrief toRule(ReportFindingGroup group) {
		return new RuleBrief(group.code(), group.title(), group.category(), group.severity(), group.occurrences().size());
	}

	record ScanOverview(
			String assetUrl,
			ScanStatus status,
			boolean complete,
			List<String> limitations,
			ScanFindingSummary summary,
			List<RuleBrief> rules) {
	}

	record RuleBrief(String code, String title, FindingCategory category, Severity severity, int addresses) {
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
