package Security_Scanner.Security_Scanner.dto;

import java.time.Instant;

/**
 * Ответ с данными актива.
 * Содержит projectId вместо сущности Project, чтобы не тянуть ленивую связь.
 */
public record AssetResponse(

		Long id,
		Long projectId,
		String name,
		String baseUrl,
		boolean active,
		Instant createdAt,
		Instant updatedAt

) {
}
