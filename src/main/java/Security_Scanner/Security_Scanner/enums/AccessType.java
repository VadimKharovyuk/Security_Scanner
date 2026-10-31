package Security_Scanner.Security_Scanner.enums;

/**
 * Тип доступа, проверяемый отдельно (раздел 11.1).
 */
public enum AccessType {

	APPLICATION_MEDIATED("Доступ к БД через уязвимость приложения и его подключение"),
	DIRECT_NETWORK("Прямой сетевой доступ к серверу БД"),
	INFRASTRUCTURE("Доступ к другим внутренним ресурсам инфраструктуры");

	private final String name;

	AccessType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
