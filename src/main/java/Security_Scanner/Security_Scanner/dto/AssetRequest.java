package Security_Scanner.Security_Scanner.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Запрос на добавление актива к проекту.
 * Обычный класс (не record), чтобы работать и с REST JSON, и с Thymeleaf-формами.
 */
@Getter
@Setter
@NoArgsConstructor
public class AssetRequest {

	@NotNull(message = "Идентификатор проекта обязателен")
	private Long projectId;

	@NotBlank(message = "Название актива обязательно")
	@Size(max = 150, message = "Название актива не должно превышать 150 символов")
	private String name;

	@NotBlank(message = "URL актива обязателен")
	@Size(max = 2048, message = "URL не должен превышать 2048 символов")
	private String baseUrl;

}
