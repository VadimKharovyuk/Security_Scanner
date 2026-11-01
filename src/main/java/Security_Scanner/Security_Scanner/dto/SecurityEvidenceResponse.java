package Security_Scanner.Security_Scanner.dto;

import Security_Scanner.Security_Scanner.enums.EvidenceType;

/**
 * Техническое доказательство находки.
 */
public record SecurityEvidenceResponse(

		Long id,
		EvidenceType type,
		String content,
		String requestSnippet,
		String responseSnippet

) {
}
