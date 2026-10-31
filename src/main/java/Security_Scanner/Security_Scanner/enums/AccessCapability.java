package Security_Scanner.Security_Scanner.enums;

/**
 * Подтверждённая возможность доступа к БД (раздел 11).
 * Каждая возможность подтверждается отдельно.
 */
public enum AccessCapability {

	READ("Подтверждено чтение данных"),
	WRITE("Подтверждено изменение тестовых данных"),
	EXECUTE("Подтверждено выполнение запросов или процедур"),
	ADMIN("Подтверждены административные привилегии");

	private final String name;

	AccessCapability(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
