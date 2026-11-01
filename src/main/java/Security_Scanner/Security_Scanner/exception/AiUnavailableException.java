package Security_Scanner.Security_Scanner.exception;

/**
 * AI-анализ недоступен: не задан ключ или модель не вернула ответ.
 */
public class AiUnavailableException extends RuntimeException {

	public AiUnavailableException(String message) {
		super(message);
	}

	public AiUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}

}
