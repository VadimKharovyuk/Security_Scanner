package Security_Scanner.Security_Scanner.service;

import java.util.List;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * Синхронизирует каталог Finding с правилами, которые объявляют сканеры.
 */
@Component
@RequiredArgsConstructor
public class FindingCatalogInitializer implements ApplicationRunner {

	private final FindingService findingService;
	private final List<SecurityScanner> scanners;

	@Override
	public void run(ApplicationArguments args) {
		List<FindingDefinition> definitions = scanners.stream()
				.flatMap(scanner -> scanner.getDefinitions().stream())
				.toList();

		findingService.syncCatalog(definitions);
	}

}
