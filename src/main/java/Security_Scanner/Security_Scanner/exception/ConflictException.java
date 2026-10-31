package Security_Scanner.Security_Scanner.exception;

/**
 * Конфликт состояния: дубликат ресурса, запрещённое удаление и т.п.
 */
public class ConflictException extends RuntimeException {

	public ConflictException(String message) {
		super(message);
	}

}
