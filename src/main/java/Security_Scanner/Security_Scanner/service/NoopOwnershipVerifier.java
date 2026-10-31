package Security_Scanner.Security_Scanner.service;

import java.time.Instant;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.dto.OwnershipCheckResult;
import Security_Scanner.Security_Scanner.enums.OwnershipStatus;
import Security_Scanner.Security_Scanner.model.Asset;

/**
 * MVP-реализация: проверка владения доменом отключена.
 * Возвращает NOT_REQUIRED, а не VERIFIED, чтобы не искажать данные аудита.
 */
@Component
@ConditionalOnProperty(
		name = "security-scanner.ownership.mode",
		havingValue = "disabled",
		matchIfMissing = true
)
public class NoopOwnershipVerifier implements OwnershipVerifier {

	@Override
	public OwnershipCheckResult verify(Asset asset) {
		return new OwnershipCheckResult(
				OwnershipStatus.NOT_REQUIRED,
				"Проверка владения доменом отключена",
				Instant.now()
		);
	}

}
