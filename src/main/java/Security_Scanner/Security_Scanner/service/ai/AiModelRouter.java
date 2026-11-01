package Security_Scanner.Security_Scanner.service.ai;

import java.util.Map;

import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.stereotype.Service;

import Security_Scanner.Security_Scanner.config.OpenRouterProperties;
import Security_Scanner.Security_Scanner.enums.AiTaskType;
import lombok.RequiredArgsConstructor;

/**
 * Выбирает модель и её параметры для типа задачи.
 * Поля, не заданные для задачи, берутся из общих настроек.
 */
@Service
@RequiredArgsConstructor
public class AiModelRouter {

	private final OpenRouterProperties properties;

	public ModelSettings settingsFor(AiTaskType task) {
		OpenRouterProperties.TaskSettings override = properties.getTasks().get(task);

		if (override == null) {
			return new ModelSettings(properties.getModel(), properties.getTemperature(), properties.getMaxTokens());
		}

		return new ModelSettings(
				override.getModel() != null ? override.getModel() : properties.getModel(),
				override.getTemperature() != null ? override.getTemperature() : properties.getTemperature(),
				override.getMaxTokens() != null ? override.getMaxTokens() : properties.getMaxTokens());
	}

	OpenAiChatOptions.Builder optionsFor(AiTaskType task) {
		ModelSettings settings = settingsFor(task);

		return OpenAiChatOptions.builder()
				.model(settings.model())
				.temperature(settings.temperature())
				.maxTokens(settings.maxTokens())
				.extraBody(Map.of("provider", Map.of("data_collection", properties.getDataCollection())));
	}

	public record ModelSettings(String model, Double temperature, Integer maxTokens) {
	}

}
