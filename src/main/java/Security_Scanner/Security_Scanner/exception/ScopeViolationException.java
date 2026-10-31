package Security_Scanner.Security_Scanner.exception;

/**
 * Нарушение разрешённой области сканирования.
 */
public class ScopeViolationException extends RuntimeException {

	public ScopeViolationException(String message) {
		super(message);
	}

}
