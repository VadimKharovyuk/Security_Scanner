package Security_Scanner.Security_Scanner.service.scan;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Завершает сканирования, прерванные остановкой приложения.
 * Выполняется до старта веб-сервера, поэтому не может затронуть только что созданные сканирования.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "security-scanner.recovery.enabled", havingValue = "true", matchIfMissing = true)
public class ScanRecoveryInitializer implements SmartInitializingSingleton {

	private final ScanRecoveryService recoveryService;

	@Override
	public void afterSingletonsInstantiated() {
		int recovered = recoveryService.recoverInterrupted();
		if (recovered > 0) {
			log.warn("Завершено прерванных сканирований: {}", recovered);
		}
	}

}
