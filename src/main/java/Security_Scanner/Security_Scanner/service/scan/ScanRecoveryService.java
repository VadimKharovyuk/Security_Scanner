package Security_Scanner.Security_Scanner.service.scan;

import java.time.Instant;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.enums.ScanEventType;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanEvent;
import Security_Scanner.Security_Scanner.model.ScanTask;
import Security_Scanner.Security_Scanner.repository.ScanEventRepository;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.repository.ScanTaskRepository;
import lombok.RequiredArgsConstructor;

/**
 * Завершает сканирования, которые больше никто не выполняет.
 * Прерванные сканирования не запускаются повторно: новый трафик к цели отправляется только по запросу пользователя.
 */
@Service
@RequiredArgsConstructor
public class ScanRecoveryService {

	static final String RESTART_MESSAGE = "Сканирование прервано перезапуском приложения";

	static final String QUEUE_FULL_MESSAGE = "Очередь сканирований переполнена";

	static final String INTERNAL_ERROR_MESSAGE = "Внутренняя ошибка при выполнении сканирования";

	private static final List<ScanStatus> ACTIVE_STATUSES = List.of(
			ScanStatus.QUEUED,
			ScanStatus.RUNNING,
			ScanStatus.ANALYZING,
			ScanStatus.VALIDATING);

	private final ScanRepository scanRepository;
	private final ScanTaskRepository scanTaskRepository;
	private final ScanEventRepository scanEventRepository;

	/**
	 * Завершает все активные сканирования. Вызывается при старте, пока ни одно из них не выполняется.
	 *
	 * @return число завершённых сканирований
	 */
	@Transactional
	public int recoverInterrupted() {
		List<Scan> scans = scanRepository.findByStatusIn(ACTIVE_STATUSES);
		scans.forEach(scan -> interrupt(scan, RESTART_MESSAGE));
		return scans.size();
	}

	/**
	 * Завершает одно сканирование. Отдельная транзакция нужна для вызова из обработчика AFTER_COMMIT.
	 */
	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void abort(Long scanId, String message) {
		scanRepository.findById(scanId)
				.filter(scan -> ACTIVE_STATUSES.contains(scan.getStatus()))
				.ifPresent(scan -> interrupt(scan, message));
	}

	private void interrupt(Scan scan, String message) {
		Instant now = Instant.now();

		for (ScanTask task : scanTaskRepository.findByScanIdOrderByIdAsc(scan.getId())) {
			if (task.getStatus() == ScanTaskStatus.RUNNING) {
				task.setStatus(ScanTaskStatus.FAILED);
				task.setErrorMessage(message);
				task.setFinishedAt(now);
			}
			else if (task.getStatus() == ScanTaskStatus.PENDING || task.getStatus() == ScanTaskStatus.QUEUED) {
				task.setStatus(ScanTaskStatus.SKIPPED);
				task.setFinishedAt(now);
			}
		}

		ScanEvent event = new ScanEvent();
		event.setScan(scan);
		event.setMessage(message);

		if (scan.isCancelRequested()) {
			scan.setStatus(ScanStatus.CANCELLED);
			event.setType(ScanEventType.SCAN_CANCELLED);
		}
		else {
			scan.setStatus(ScanStatus.FAILED);
			scan.setErrorMessage(message);
			event.setType(ScanEventType.SCAN_FAILED);
		}

		scan.setFinishedAt(now);
		scanEventRepository.save(event);
	}

}
