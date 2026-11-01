package Security_Scanner.Security_Scanner.dto;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;

/**
 * Элемент каталога находок.
 */
public record FindingResponse(

		Long id,
		String code,
		String title,
		String description,
		FindingCategory category,
		Severity severity,
		Confidence confidence,
		String recommendation,
		String reference

) {
}
