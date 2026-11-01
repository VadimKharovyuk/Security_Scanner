package Security_Scanner.Security_Scanner.service;

import java.time.Instant;

import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.enums.ScannerType;

/**
 * Заглушка сканера для проверки жизненного цикла оркестратора.
 */
@Component
public class StubScanner implements SecurityScanner {

	@Override
	public ScannerType getType() {
		return ScannerType.STUB;
	}

	@Override
	public ScanResult execute(ScanContext context) {
		Instant startedAt = Instant.now();
		return ScanResult.success("Заглушка выполнена для " + context.baseUrl(), startedAt);
	}

}
