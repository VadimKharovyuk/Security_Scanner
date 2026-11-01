package Security_Scanner.Security_Scanner.service.scanner;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;

/**
 * Описание правила проверки. Сканер объявляет такие определения,
 * каталог Finding синхронизируется с ними при старте приложения.
 */
public record FindingDefinition(

		String code,
		String title,
		String description,
		FindingCategory category,
		Severity severity,
		Confidence confidence,
		String recommendation,
		String reference

) {
}
