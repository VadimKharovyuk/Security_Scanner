package Security_Scanner.Security_Scanner.enums;

/**
 * Тип сканера, подключаемого через интерфейс SecurityScanner (раздел 16).
 */
public enum ScannerType {

	HTTP("Проверки HTTP-конфигурации и заголовков безопасности"),
	TLS("Проверки TLS-конфигурации и сертификатов"),
	OWASP_ZAP("Динамический анализ через OWASP ZAP"),
	DNS("Проверки DNS-конфигурации"),
	STUB("Заглушка для проверки оркестратора");

	private final String name;

	ScannerType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
