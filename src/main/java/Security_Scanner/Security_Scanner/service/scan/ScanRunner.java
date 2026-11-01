package Security_Scanner.Security_Scanner.service.scan;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.core.task.TaskExecutor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.event.ScanCreatedEvent;
import Security_Scanner.Security_Scanner.service.scanner.ScanContext;
import Security_Scanner.Security_Scanner.service.scanner.ScanResult;
import Security_Scanner.Security_Scanner.service.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Асинхронный исполнитель сканирования.
 * Запускается после коммита транзакции создания Scan.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ScanRunner {

	private final ScanOrchestrator orchestrator;
	private final ScanRecoveryService recoveryService;
	private final List<SecurityScanner> scanners;
	private final TaskExecutor scanExecutor;

	@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
	public void onScanCreated(ScanCreatedEvent event) {
		try {
			scanExecutor.execute(() -> execute(event.scanId()));
		}
		catch (TaskRejectedException exception) {
			log.warn("Сканирование {} отклонено пулом потоков", event.scanId(), exception);
			recoveryService.abort(event.scanId(), ScanRecoveryService.QUEUE_FULL_MESSAGE);
		}
	}

	public void execute(Long scanId) {
		try {
			run(scanId);
		}
		catch (RuntimeException exception) {
			log.error("Сканирование {} завершилось внутренней ошибкой", scanId, exception);
			recoveryService.abort(scanId, ScanRecoveryService.INTERNAL_ERROR_MESSAGE);
		}
	}

	private void run(Long scanId) {
		ScanOrchestrator.RunData data = orchestrator.prepareRun(scanId);
		orchestrator.markRunning(scanId);
		log.info("Сканирование {}: запуск, адрес {}, задач: {}", scanId, data.baseUrl(), data.tasks().size());

		Map<ScannerType, SecurityScanner> scannersByType = scanners.stream()
				.collect(Collectors.toMap(SecurityScanner::getType, Function.identity()));

		for (ScanOrchestrator.TaskData task : data.tasks()) {
			if (orchestrator.isCancelRequested(scanId)) {
				log.info("Сканирование {}: сканер {} пропущен, запрошена отмена", scanId, task.scannerType());
				orchestrator.skipTask(task.taskId());
				continue;
			}

			orchestrator.startTask(task.taskId());

			SecurityScanner scanner = scannersByType.get(task.scannerType());
			if (scanner == null) {
				log.warn("Сканирование {}: сканер {} не найден", scanId, task.scannerType());
				orchestrator.failTask(task.taskId(), "Сканер не найден: " + task.scannerType());
				continue;
			}

			log.info("Сканирование {}: сканер {} запущен", scanId, task.scannerType());
			Instant startedAt = Instant.now();

			try {
				ScanContext context = new ScanContext(
						data.scanId(),
						task.taskId(),
						data.assetId(),
						data.baseUrl(),
						scanner.getTimeout(),
						() -> orchestrator.isCancelRequested(scanId));

				ScanResult result = scanner.execute(context);

				long elapsed = Duration.between(startedAt, Instant.now()).toMillis();

				if (result.success()) {
					log.info("Сканирование {}: сканер {} завершён за {} мс, находок: {}. {}",
							scanId, task.scannerType(), elapsed, result.findings().size(), singleLine(result.message()));
					orchestrator.completeTask(task.taskId(), result);
				}
				else {
					log.warn("Сканирование {}: сканер {} завершился ошибкой за {} мс: {}",
							scanId, task.scannerType(), elapsed, singleLine(result.message()));
					orchestrator.failTask(task.taskId(), result.message());
				}
			}
			catch (Exception exception) {
				log.warn("Задача {} завершилась ошибкой", task.taskId(), exception);
				String message = exception.getMessage() != null
						? exception.getMessage()
						: exception.getClass().getSimpleName();
				orchestrator.failTask(task.taskId(), message);
			}
		}

		orchestrator.finish(scanId);
	}

	/**
	 * Сообщение сканера может содержать данные с сайта: переводы строк подделали бы записи лога.
	 */
	private static String singleLine(String message) {
		return message == null ? "" : message.replaceAll("[\\r\\n]+", " ");
	}

}
