package Security_Scanner.Security_Scanner.dto.project;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Запрос на создание или обновление проекта.
 * Обычный класс (не record), чтобы работать и с REST JSON, и с Thymeleaf-формами.
 */
@Getter
@Setter
@NoArgsConstructor
public class ProjectRequest {

	@NotBlank(message = "Название проекта обязательно")
	@Size(max = 150, message = "Название проекта не должно превышать 150 символов")
	private String name;

	@Size(max = 500, message = "Описание не должно превышать 500 символов")
	private String description;

}
