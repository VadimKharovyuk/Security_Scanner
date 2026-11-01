package Security_Scanner.Security_Scanner.service;

import Security_Scanner.Security_Scanner.enums.ScannerType;

/**
 * Единый интерфейс сканера (раздел 16).
 * Реализации подключаются в Scan Orchestrator без изменения его кода.
 */
public interface SecurityScanner {

	ScannerType getType();

	ScanResult execute(ScanContext context);

}
