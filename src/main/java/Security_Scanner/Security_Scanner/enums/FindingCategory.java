package Security_Scanner.Security_Scanner.enums;

/**
 * Категория находки. Используется для группировки в отчётах и UI.
 */
public enum FindingCategory {

	HEADERS("Заголовки безопасности HTTP"),
	TRANSPORT("Транспортная безопасность и HTTPS"),
	COOKIES("Флаги безопасности cookie"),
	INFORMATION_DISCLOSURE("Раскрытие технической информации"),
	CONFIGURATION("Конфигурация приложения");

	private final String name;

	FindingCategory(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
