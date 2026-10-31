package Security_Scanner.Security_Scanner.enums;

/**
 * Статус перехода в Attack Graph (раздел 9).
 * Окончательное состояние ребра определяется техническими результатами, не AI.
 */
public enum AttackPathEdgeStatus {

	THEORETICAL("Переход возможен теоретически, технически не проверялся"),
	DETECTED("Переход обнаружен, но эксплуатация не подтверждена"),
	VALIDATED("Переход подтверждён технической проверкой"),
	BLOCKED("Переход проверен и оказался невозможен"),
	NOT_TESTED("Переход не проверялся из-за ограничений или политики");

	private final String name;

	AttackPathEdgeStatus(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
