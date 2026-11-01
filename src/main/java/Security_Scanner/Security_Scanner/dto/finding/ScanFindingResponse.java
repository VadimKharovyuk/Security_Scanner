package Security_Scanner.Security_Scanner.dto.finding;

import java.time.Instant;
import java.util.List;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.Severity;

/**
 * Находка в конкретном сканировании.
 */
public record ScanFindingResponse(

		Long id,
		Long scanId,
		Long findingId,
		String code,
		String title,
		String description,
		FindingCategory category,
		FindingStatus status,
		Severity severity,
		Confidence confidence,
		String recommendation,
		String reference,
		String url,
		Instant detectedAt,
		List<SecurityEvidenceResponse> evidence

) {
}
