package Security_Scanner.Security_Scanner.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Пул потоков для выполнения сканирований.
 * In-process, без Redis и Docker.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

	@Bean(name = "scanExecutor")
	public ThreadPoolTaskExecutor scanExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(2);
		executor.setMaxPoolSize(4);
		executor.setQueueCapacity(50);
		executor.setThreadNamePrefix("scan-");
		executor.initialize();
		return executor;
	}

}
