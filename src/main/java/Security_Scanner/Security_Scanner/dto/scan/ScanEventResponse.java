package Security_Scanner.Security_Scanner.dto.scan;

import java.time.Instant;

import Security_Scanner.Security_Scanner.enums.ScanEventType;

/**
 * Событие сканирования в ответе.
 */
public record ScanEventResponse(

		Long id,
		ScanEventType type,
		String message,
		Instant createdAt

) {
}
