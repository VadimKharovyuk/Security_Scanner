package Security_Scanner.Security_Scanner.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Запрос на запуск сканирования.
 */
@Getter
@Setter
@NoArgsConstructor
public class ScanRequest {

	@NotNull(message = "Идентификатор актива обязателен")
	private Long assetId;

}
