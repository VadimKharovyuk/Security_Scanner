package Security_Scanner.Security_Scanner.dto.finding;

import java.util.Map;

import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.Severity;

/**
 * Сводка находок сканирования. Находки FALSE_POSITIVE в bySeverity не учитываются.
 */
public record ScanFindingSummary(
		Long scanId,
		long total,
		Map<Severity, Long> bySeverity,
		Map<FindingStatus, Long> byStatus
) {
}
