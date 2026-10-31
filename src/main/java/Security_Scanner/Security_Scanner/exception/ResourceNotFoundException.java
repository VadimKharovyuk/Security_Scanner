package Security_Scanner.Security_Scanner.exception;

/**
 * Запрошенный ресурс не найден.
 */
public class ResourceNotFoundException extends RuntimeException {

	public ResourceNotFoundException(String message) {
		super(message);
	}

}
