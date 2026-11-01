package Security_Scanner.Security_Scanner.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

/**
 * Настройки подключения к OWASP ZAP и ограничения обхода сайта.
 */
@Component
@ConfigurationProperties(prefix = "security-scanner.zap")
@Getter
@Setter
public class ZapProperties {

	private String url = "http://127.0.0.1:8090";

	private String apiKey;

	/**
	 * Имя компьютера с приложением, как его видит ZAP: для контейнера localhost — это сам контейнер.
	 */
	private String localTargetHost = "host.docker.internal";

	private Duration timeout = Duration.ofMinutes(10);

	private Duration pollInterval = Duration.ofSeconds(2);

	private int maxDepth = 5;

	private int maxSpiderMinutes = 5;

	private int spiderThreads = 2;

	private int maxFindings = 500;

}
