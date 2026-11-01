package Security_Scanner.Security_Scanner.service.asset;

import Security_Scanner.Security_Scanner.dto.asset.OwnershipCheckResult;
import Security_Scanner.Security_Scanner.model.Asset;

/**
 * Проверка владения активом.
 * Реализация выбирается через security-scanner.ownership.mode:
 * disabled (MVP) — NoopOwnershipVerifier, required — проверка домена.
 */
public interface OwnershipVerifier {

	OwnershipCheckResult verify(Asset asset);

}
