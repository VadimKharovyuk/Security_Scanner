package Security_Scanner.Security_Scanner.service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.event.ScanCreatedEvent;
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
	private final List<SecurityScanner> scanners;

	@Async("scanExecutor")
	@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
	public void onScanCreated(ScanCreatedEvent event) {
		execute(event.scanId());
	}

	public void execute(Long scanId) {
		ScanOrchestrator.RunData data = orchestrator.prepareRun(scanId);
		orchestrator.markRunning(scanId);

		Map<ScannerType, SecurityScanner> scannersByType = scanners.stream()
				.collect(Collectors.toMap(SecurityScanner::getType, Function.identity()));

		for (ScanOrchestrator.TaskData task : data.tasks()) {
			if (orchestrator.isCancelRequested(scanId)) {
				orchestrator.skipTask(task.taskId());
				continue;
			}

			orchestrator.startTask(task.taskId());

			SecurityScanner scanner = scannersByType.get(task.scannerType());
			if (scanner == null) {
				orchestrator.failTask(task.taskId(), "Сканер не найден: " + task.scannerType());
				continue;
			}

			try {
				ScanContext context = new ScanContext(
						data.scanId(),
						task.taskId(),
						data.assetId(),
						data.baseUrl(),
						orchestrator.getTaskTimeout());

				ScanResult result = scanner.execute(context);

				if (result.success()) {
					orchestrator.completeTask(task.taskId(), result);
				}
				else {
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

}
