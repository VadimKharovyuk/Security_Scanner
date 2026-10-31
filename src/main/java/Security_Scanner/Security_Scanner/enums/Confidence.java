package Security_Scanner.Security_Scanner.enums;

/**
 * Уровень уверенности в результате (раздел 8).
 * Хранится отдельно от Severity.
 */
public enum Confidence {

	HIGH("Высокая уверенность, подтверждена техническими данными"),
	MEDIUM("Средняя уверенность, требуются дополнительные проверки"),
	LOW("Низкая уверенность, результат предварительный");

	private final String name;

	Confidence(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
