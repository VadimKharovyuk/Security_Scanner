package Security_Scanner.Security_Scanner.enums;

/**
 * Тип технического доказательства, приложенного к находке.
 */
public enum EvidenceType {

	RESPONSE_HEADER("HTTP-заголовок ответа"),
	RESPONSE_BODY("Фрагмент тела ответа"),
	REQUEST("Параметры выполненного запроса"),
	TLS_CERTIFICATE("Данные TLS-сертификата"),
	TEXT("Текстовое пояснение");

	private final String name;

	EvidenceType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
