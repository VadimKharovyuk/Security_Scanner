package Security_Scanner.Security_Scanner.enums;

/**
 * Тип задачи для AiProviderRouter (раздел 13).
 */
public enum AiTaskType {

	FINDING_CLASSIFICATION("Классификация и категоризация Finding"),
	FINDING_ANALYSIS("Анализ отдельной уязвимости"),
	RISK_ASSESSMENT("Оценка риска и потенциального воздействия"),
	ATTACK_PATH_ANALYSIS("Анализ сложных цепочек атаки"),
	HARDENING_RECOMMENDATION("Рекомендации по усилению защиты"),
	REPORT_GENERATION("Подготовка текста итогового отчёта");

	private final String name;

	AiTaskType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
