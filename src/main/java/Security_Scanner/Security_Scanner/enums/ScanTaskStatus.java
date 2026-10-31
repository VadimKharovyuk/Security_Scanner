package Security_Scanner.Security_Scanner.enums;

/**
 * Статус отдельной задачи сканирования (ScanTask).
 */
public enum ScanTaskStatus {

	PENDING("Задача создана, но ещё не поставлена в очередь"),
	QUEUED("Задача поставлена в очередь на выполнение"),
	RUNNING("Задача выполняется"),
	COMPLETED("Задача завершена успешно"),
	FAILED("Задача завершилась ошибкой"),
	CANCELLED("Задача отменена"),
	SKIPPED("Задача пропущена по правилам области или политики сканирования");

	private final String name;

	ScanTaskStatus(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
