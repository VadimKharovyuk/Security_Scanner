package Security_Scanner.Security_Scanner.dto.asset;

import java.time.Instant;

import Security_Scanner.Security_Scanner.enums.OwnershipStatus;

/**
 * Результат проверки владения активом.
 */
public record OwnershipCheckResult(

		OwnershipStatus status,
		String message,
		Instant checkedAt

) {
}
