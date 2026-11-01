package Security_Scanner.Security_Scanner.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Пул потоков для выполнения сканирований.
 * In-process, без Redis и Docker.
 */
@Configuration
public class AsyncConfig {

	private static final int SHUTDOWN_TIMEOUT_SECONDS = 60;

	@Bean(name = "scanExecutor")
	public ThreadPoolTaskExecutor scanExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(2);
		executor.setMaxPoolSize(4);
		executor.setQueueCapacity(50);
		executor.setThreadNamePrefix("scan-");
		// Не успевшие завершиться сканирования закроет ScanRecoveryInitializer при следующем старте.
		executor.setWaitForTasksToCompleteOnShutdown(true);
		executor.setAwaitTerminationSeconds(SHUTDOWN_TIMEOUT_SECONDS);
		executor.initialize();
		return executor;
	}

}
