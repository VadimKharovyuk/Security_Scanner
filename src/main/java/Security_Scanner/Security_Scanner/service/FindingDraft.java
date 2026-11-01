package Security_Scanner.Security_Scanner.service;

import java.util.List;

/**
 * Находка, обнаруженная сканером. Сохраняется оркестратором в рамках транзакции задачи.
 */
public record FindingDraft(

		FindingDefinition definition,
		String url,
		List<EvidenceDraft> evidence

) {

	public FindingDraft {
		evidence = evidence == null ? List.of() : List.copyOf(evidence);
	}

	public static FindingDraft of(FindingDefinition definition, String url, EvidenceDraft... evidence) {
		return new FindingDraft(definition, url, List.of(evidence));
	}

}
