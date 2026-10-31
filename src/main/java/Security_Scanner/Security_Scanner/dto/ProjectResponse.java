package Security_Scanner.Security_Scanner.dto;

import java.time.Instant;

/**
 * Ответ с данными проекта.
 */
public record ProjectResponse(

		Long id,
		String name,
		String description,
		Instant createdAt,
		Instant updatedAt

) {
}
