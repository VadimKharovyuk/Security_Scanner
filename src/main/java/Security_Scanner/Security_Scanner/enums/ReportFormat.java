package Security_Scanner.Security_Scanner.enums;

/**
 * Формат итогового отчёта (раздел 18).
 */
public enum ReportFormat {

	HTML("Отчёт в формате HTML"),
	PDF("Отчёт в формате PDF"),
	JSON("Отчёт в формате JSON");

	private final String name;

	ReportFormat(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
