package Security_Scanner.Security_Scanner.enums;

/**
 * Статус Finding (раздел 8).
 * RESOLVED назначается только после повторной проверки, подтверждающей устранение.
 */
public enum FindingStatus {

	OPEN("Уязвимость обнаружена и ожидает проверки"),
	CONFIRMED("Эксплуатация подтверждена техническими доказательствами"),
	FALSE_POSITIVE("Обнаружение признано ложным"),
	RESOLVED("Устранение подтверждено повторной проверкой");

	private final String name;

	FindingStatus(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
