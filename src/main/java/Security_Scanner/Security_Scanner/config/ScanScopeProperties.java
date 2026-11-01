package Security_Scanner.Security_Scanner.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

/**
 * Настройки разрешённой области сканирования.
 * security-scanner.scope.allowed-hosts=webscraft.org,www.webscraft.org
 * security-scanner.scope.allow-subdomains=false
 */
@Component
@ConfigurationProperties(prefix = "security-scanner.scope")
@Getter
@Setter
public class ScanScopeProperties {

	private List<String> allowedHosts = new ArrayList<>();

	private boolean allowSubdomains = false;

	/**
	 * Порты, на которых разрешён только http(s)://localhost:порт. Пусто — localhost запрещён.
	 */
	private List<Integer> allowedLocalPorts = new ArrayList<>();

}
