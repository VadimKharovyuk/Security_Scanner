package Security_Scanner.Security_Scanner.config;

import java.util.EnumMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.enums.AiTaskType;
import lombok.Getter;
import lombok.Setter;

/**
 * Настройки OpenRouter. Значения верхнего уровня действуют для всех задач,
 * в tasks указываются только отличия для конкретного типа задачи.
 */
@Component
@ConfigurationProperties(prefix = "app.openrouter")
@Getter
@Setter
public class OpenRouterProperties {

	private String apiKey;

	private String baseUrl = "https://openrouter.ai/api/v1";

	private String model;

	private Double temperature;

	private Integer maxTokens;

	/**
	 * Политика провайдера модели в отношении данных запроса: deny запрещает их сбор.
	 */
	private String dataCollection = "deny";

	private Map<AiTaskType, TaskSettings> tasks = new EnumMap<>(AiTaskType.class);

	@Getter
	@Setter
	public static class TaskSettings {

		private String model;

		private Double temperature;

		private Integer maxTokens;

	}

}
