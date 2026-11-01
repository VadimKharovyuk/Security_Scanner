package Security_Scanner.Security_Scanner.service.scanner.zap;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Предупреждение из ответа ZAP API. Значения приходят с проверяемого сайта и не считаются доверенными.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
record ZapAlert(

		String name,
		String alertRef,
		String pluginId,
		String risk,
		String confidence,
		String url,
		String method,
		String param,
		String evidence,
		String other,
		String description,
		String solution,
		String reference

) {
}
