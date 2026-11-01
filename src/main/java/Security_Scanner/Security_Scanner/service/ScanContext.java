package Security_Scanner.Security_Scanner.service;

import java.time.Duration;

/**
 * Контекст выполнения одной задачи сканирования.
 */
public record ScanContext(

		Long scanId,
		Long taskId,
		Long assetId,
		String baseUrl,
		Duration timeout

) {
}
