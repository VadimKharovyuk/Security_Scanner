package Security_Scanner.Security_Scanner.enums;

/**
 * Тип события сканирования.
 */
public enum ScanEventType {

	SCAN_CREATED("Сканирование создано"),
	SCAN_STARTED("Сканирование запущено"),
	TASK_STARTED("Задача запущена"),
	TASK_COMPLETED("Задача завершена"),
	TASK_FAILED("Задача завершилась ошибкой"),
	TASK_SKIPPED("Задача пропущена"),
	SCAN_COMPLETED("Сканирование завершено"),
	SCAN_FAILED("Сканирование завершилось ошибкой"),
	SCAN_CANCELLED("Сканирование отменено");

	private final String name;

	ScanEventType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
