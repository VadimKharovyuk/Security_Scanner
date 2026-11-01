package Security_Scanner.Security_Scanner.service.scanner;

import java.util.List;

import Security_Scanner.Security_Scanner.enums.ScannerType;

/**
 * Единый интерфейс сканера (раздел 16).
 * Реализации подключаются в Scan Orchestrator без изменения его кода.
 */
public interface SecurityScanner {

	ScannerType getType();

	ScanResult execute(ScanContext context);

	/**
	 * Правила проверки, которые сканер умеет обнаруживать.
	 * Используются для синхронизации каталога Finding.
	 */
	default List<FindingDefinition> getDefinitions() {
		return List.of();
	}

}
