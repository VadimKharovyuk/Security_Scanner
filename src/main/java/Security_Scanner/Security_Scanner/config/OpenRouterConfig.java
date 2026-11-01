package Security_Scanner.Security_Scanner.config;

import java.time.Duration;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Подключение к модели через OpenRouter. Без ключа бин не создаётся, и приложение работает без AI.
 */
@Configuration
public class OpenRouterConfig {

	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);

	private static final int MAX_RETRIES = 1;

	@Bean
	@ConditionalOnExpression("!'${app.openrouter.api-key:}'.isBlank()")
	public ChatModel openRouterChatModel(OpenRouterProperties properties) {
		return OpenAiChatModel.builder()
				.options(OpenAiChatOptions.builder()
						.baseUrl(properties.getBaseUrl())
						.apiKey(properties.getApiKey())
						.model(properties.getModel())
						.timeout(REQUEST_TIMEOUT)
						.maxRetries(MAX_RETRIES)
						.build())
				.build();
	}

}
