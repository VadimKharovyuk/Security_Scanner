package Security_Scanner.Security_Scanner.enums;

/**
 * Уровень критичности Finding (раздел 8).
 * Хранится отдельно от Confidence.
 */
public enum Severity {

	CRITICAL("Критическая уязвимость с максимальным воздействием"),
	HIGH("Высокий уровень риска"),
	MEDIUM("Средний уровень риска"),
	LOW("Низкий уровень риска"),
	INFO("Информационная находка без прямого риска");

	private final String name;

	Severity(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
