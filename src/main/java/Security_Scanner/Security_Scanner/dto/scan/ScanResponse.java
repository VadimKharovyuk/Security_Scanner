package Security_Scanner.Security_Scanner.dto.scan;

import java.time.Instant;
import java.util.List;

import Security_Scanner.Security_Scanner.dto.scanevent.ScanEventResponse;
import Security_Scanner.Security_Scanner.dto.scantask.ScanTaskResponse;
import Security_Scanner.Security_Scanner.enums.ScanStatus;

/**
 * Сканирование в ответе.
 */
public record ScanResponse(

		Long id,
		Long assetId,
		ScanStatus status,
		boolean cancelRequested,
		String errorMessage,
		Instant createdAt,
		Instant startedAt,
		Instant finishedAt,
		List<ScanTaskResponse> tasks,
		List<ScanEventResponse> events

) {
}
