package Security_Scanner.Security_Scanner.dto.report;

import java.util.List;

import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;

/**
 * Одно правило проверки со всеми адресами, где оно сработало.
 * Severity — наибольшая среди обнаружений.
 */
public record ReportFindingGroup(

		String code,
		String title,
		String description,
		FindingCategory category,
		Severity severity,
		String recommendation,
		String reference,
		List<ScanFindingResponse> occurrences

) {
}
