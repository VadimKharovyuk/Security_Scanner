package Security_Scanner.Security_Scanner.service.scanner;

import Security_Scanner.Security_Scanner.enums.EvidenceType;

/**
 * Доказательство, подготовленное сканером до сохранения в БД.
 * Секреты и персональные данные должны быть отредактированы сканером.
 */
public record EvidenceDraft(

		EvidenceType type,
		String content,
		String requestSnippet,
		String responseSnippet

) {

	public static EvidenceDraft of(EvidenceType type, String content) {
		return new EvidenceDraft(type, content, null, null);
	}

}
