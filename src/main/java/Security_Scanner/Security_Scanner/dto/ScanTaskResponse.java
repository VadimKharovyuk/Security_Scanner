package Security_Scanner.Security_Scanner.dto;

import java.time.Instant;

import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.enums.ScannerType;

/**
 * Задача сканирования в ответе.
 */
public record ScanTaskResponse(

		Long id,
		ScannerType scannerType,
		ScanTaskStatus status,
		String errorMessage,
		Instant startedAt,
		Instant finishedAt

) {
}
