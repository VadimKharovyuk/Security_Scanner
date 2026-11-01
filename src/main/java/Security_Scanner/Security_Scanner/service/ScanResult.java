package Security_Scanner.Security_Scanner.service;

import java.time.Instant;

/**
 * Результат выполнения сканера.
 */
public record ScanResult(

		boolean success,
		String message,
		Instant startedAt,
		Instant finishedAt

) {

	public static ScanResult success(String message, Instant startedAt) {
		return new ScanResult(true, message, startedAt, Instant.now());
	}

	public static ScanResult failure(String message, Instant startedAt) {
		return new ScanResult(false, message, startedAt, Instant.now());
	}

}
