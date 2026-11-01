package Security_Scanner.Security_Scanner.dto.report;

import java.time.Instant;
import java.util.List;

import Security_Scanner.Security_Scanner.dto.finding.ScanFindingSummary;
import Security_Scanner.Security_Scanner.dto.scan.ScanTaskResponse;
import Security_Scanner.Security_Scanner.enums.OwnershipStatus;
import Security_Scanner.Security_Scanner.enums.ScanStatus;

/**
 * Отчёт по сканированию. Находки FALSE_POSITIVE в группы не входят и видны только в сводке.
 * Отсутствие находок не означает безопасность: что не было проверено, перечислено в limitations.
 */
public record ScanReport(

		Instant generatedAt,
		Long scanId,
		String projectName,
		Long assetId,
		String assetName,
		String assetUrl,
		OwnershipStatus ownershipStatus,
		ScanStatus status,
		boolean complete,
		String errorMessage,
		Instant startedAt,
		Instant finishedAt,
		List<String> limitations,
		ScanFindingSummary summary,
		List<ReportFindingGroup> findings,
		List<ScanTaskResponse> tasks

) {
}
