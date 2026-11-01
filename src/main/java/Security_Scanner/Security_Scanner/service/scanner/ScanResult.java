package Security_Scanner.Security_Scanner.service.scanner;

import java.time.Instant;
import java.util.List;

/**
 * Результат выполнения сканера.
 */
public record ScanResult(

		boolean success,
		String message,
		Instant startedAt,
		Instant finishedAt,
		List<FindingDraft> findings

) {

	public ScanResult {
		findings = findings == null ? List.of() : List.copyOf(findings);
	}

	public static ScanResult success(String message, Instant startedAt) {
		return new ScanResult(true, message, startedAt, Instant.now(), List.of());
	}

	public static ScanResult success(String message, Instant startedAt, List<FindingDraft> findings) {
		return new ScanResult(true, message, startedAt, Instant.now(), findings);
	}

	public static ScanResult failure(String message, Instant startedAt) {
		return new ScanResult(false, message, startedAt, Instant.now(), List.of());
	}

}
