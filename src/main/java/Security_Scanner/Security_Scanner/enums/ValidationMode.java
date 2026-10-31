package Security_Scanner.Security_Scanner.enums;

/**
 * Режим технической проверки (раздел 10).
 */
public enum ValidationMode {

	PRODUCTION_SAFE("Безопасная проверка production без разрушительных операций"),
	STAGING_DEEP("Глубокая проверка в изолированной среде");

	private final String name;

	ValidationMode(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
