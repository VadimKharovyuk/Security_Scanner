package Security_Scanner.Security_Scanner.enums;

/**
 * Жизненный цикл сканирования (раздел 6 спецификации).
 */
public enum ScanStatus {

	QUEUED("Сканирование создано и ожидает запуска"),
	RUNNING("Выполняются задачи сканирования"),
	ANALYZING("Результаты сканирования анализируются"),
	VALIDATING("Выполняется техническая проверка уязвимостей"),
	COMPLETED("Сканирование завершено успешно"),
	PARTIALLY_COMPLETED("Сканирование завершено частично: часть задач не выполнена"),
	FAILED("Сканирование завершилось ошибкой"),
	CANCELLED("Сканирование отменено");

	private final String name;

	ScanStatus(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
