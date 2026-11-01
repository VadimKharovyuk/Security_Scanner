package Security_Scanner.Security_Scanner.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.ScanRequest;
import Security_Scanner.Security_Scanner.dto.ScanResponse;
import Security_Scanner.Security_Scanner.enums.OwnershipStatus;
import Security_Scanner.Security_Scanner.enums.ScanEventType;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.enums.ScannerType;
import Security_Scanner.Security_Scanner.event.ScanCreatedEvent;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.mapper.ScanMapper;
import Security_Scanner.Security_Scanner.model.Asset;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanEvent;
import Security_Scanner.Security_Scanner.model.ScanTask;
import Security_Scanner.Security_Scanner.repository.ScanEventRepository;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.repository.ScanTaskRepository;
import lombok.RequiredArgsConstructor;

/**
 * Управление жизненным циклом сканирования (раздел 6).
 */
@Service
@RequiredArgsConstructor
public class ScanOrchestrator {

	public static final int PAGE_SIZE = 20;

	private static final Duration TASK_TIMEOUT = Duration.ofSeconds(30);

	private final ScanRepository scanRepository;
	private final ScanTaskRepository scanTaskRepository;
	private final ScanEventRepository scanEventRepository;
	private final AssetService assetService;
	private final ScanMapper scanMapper;
	private final List<SecurityScanner> scanners;
	private final ApplicationEventPublisher eventPublisher;

	/**
	 * Данные, необходимые для выполнения сканирования вне транзакции создания.
	 */
	public record RunData(Long scanId, Long assetId, String baseUrl, List<TaskData> tasks) {
	}

	public record TaskData(Long taskId, ScannerType scannerType) {
	}

	@Transactional
	public ScanResponse create(ScanRequest request) {
		Asset asset = assetService.getEntity(request.getAssetId());

		if (!asset.isActive()) {
			throw new ConflictException("Актив деактивирован");
		}

		OwnershipStatus ownership = asset.getOwnershipStatus();
		if (ownership != OwnershipStatus.NOT_REQUIRED && ownership != OwnershipStatus.VERIFIED) {
			throw new ConflictException("Владение активом не подтверждено");
		}

		Scan scan = new Scan();
		scan.setAsset(asset);
		scan.setStatus(ScanStatus.QUEUED);
		scan = scanRepository.save(scan);

		for (SecurityScanner scanner : scanners) {
			ScanTask task = new ScanTask();
			task.setScan(scan);
			task.setScannerType(scanner.getType());
			task.setStatus(ScanTaskStatus.PENDING);
			scanTaskRepository.save(task);
		}

		addEvent(scan, ScanEventType.SCAN_CREATED, "Сканирование создано");

		eventPublisher.publishEvent(new ScanCreatedEvent(scan.getId()));

		return toResponse(scan);
	}

	@Transactional(readOnly = true)
	public List<ScanResponse> findAll(int page) {
		Page<Scan> result = scanRepository
				.findAllByOrderByCreatedAtDesc(PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(this::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public List<ScanResponse> findByAsset(Long assetId, int page) {
		assetService.getEntity(assetId);
		Page<Scan> result = scanRepository
				.findByAssetIdOrderByCreatedAtDesc(assetId, PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(this::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public ScanResponse findById(Long id) {
		Scan scan = getEntity(id);
		return toResponse(scan);
	}

	@Transactional
	public ScanResponse cancel(Long id) {
		Scan scan = getEntity(id);

		if (scan.getStatus() == ScanStatus.COMPLETED
				|| scan.getStatus() == ScanStatus.PARTIALLY_COMPLETED
				|| scan.getStatus() == ScanStatus.FAILED
				|| scan.getStatus() == ScanStatus.CANCELLED) {
			throw new ConflictException("Сканирование уже завершено");
		}

		scan.setCancelRequested(true);

		if (scan.getStatus() == ScanStatus.QUEUED) {
			scan.setStatus(ScanStatus.CANCELLED);
			scan.setFinishedAt(Instant.now());
		}

		scanRepository.save(scan);
		addEvent(scan, ScanEventType.SCAN_CANCELLED, "Запрошена отмена сканирования");

		return toResponse(scan);
	}

	@Transactional
	public void delete(Long id) {
		Scan scan = getEntity(id);
		scanEventRepository.deleteByScanId(id);
		scanTaskRepository.deleteByScanId(id);
		scanRepository.delete(scan);
	}

	@Transactional(readOnly = true)
	public RunData prepareRun(Long scanId) {
		Scan scan = getEntity(scanId);
		Asset asset = scan.getAsset();

		List<TaskData> tasks = scanTaskRepository.findByScanIdOrderByIdAsc(scanId).stream()
				.map(task -> new TaskData(task.getId(), task.getScannerType()))
				.toList();

		return new RunData(scanId, asset.getId(), asset.getBaseUrl(), tasks);
	}

	@Transactional
	public void markRunning(Long scanId) {
		Scan scan = getEntity(scanId);
		scan.setStatus(ScanStatus.RUNNING);
		scan.setStartedAt(Instant.now());
		scanRepository.save(scan);
		addEvent(scan, ScanEventType.SCAN_STARTED, "Сканирование запущено");
	}

	@Transactional
	public void startTask(Long taskId) {
		ScanTask task = getTask(taskId);
		task.setStatus(ScanTaskStatus.RUNNING);
		task.setStartedAt(Instant.now());
		scanTaskRepository.save(task);
		addEvent(task.getScan(), ScanEventType.TASK_STARTED,
				"Задача " + task.getScannerType() + " запущена");
	}

	@Transactional
	public void completeTask(Long taskId, ScanResult result) {
		ScanTask task = getTask(taskId);
		task.setStatus(ScanTaskStatus.COMPLETED);
		task.setFinishedAt(Instant.now());
		task.setErrorMessage(null);
		scanTaskRepository.save(task);
		addEvent(task.getScan(), ScanEventType.TASK_COMPLETED,
				"Задача " + task.getScannerType() + ": " + result.message());
	}

	@Transactional
	public void failTask(Long taskId, String message) {
		ScanTask task = getTask(taskId);
		task.setStatus(ScanTaskStatus.FAILED);
		task.setFinishedAt(Instant.now());
		task.setErrorMessage(message);
		scanTaskRepository.save(task);
		addEvent(task.getScan(), ScanEventType.TASK_FAILED,
				"Задача " + task.getScannerType() + ": " + message);
	}

	@Transactional
	public void skipTask(Long taskId) {
		ScanTask task = getTask(taskId);
		task.setStatus(ScanTaskStatus.SKIPPED);
		task.setFinishedAt(Instant.now());
		scanTaskRepository.save(task);
		addEvent(task.getScan(), ScanEventType.TASK_SKIPPED,
				"Задача " + task.getScannerType() + " пропущена");
	}

	@Transactional(readOnly = true)
	public boolean isCancelRequested(Long scanId) {
		return scanRepository.findById(scanId)
				.map(Scan::isCancelRequested)
				.orElse(true);
	}

	@Transactional
	public void finish(Long scanId) {
		Scan scan = getEntity(scanId);
		List<ScanTask> tasks = scanTaskRepository.findByScanIdOrderByIdAsc(scanId);

		long completed = tasks.stream().filter(task -> task.getStatus() == ScanTaskStatus.COMPLETED).count();
		long failed = tasks.stream().filter(task -> task.getStatus() == ScanTaskStatus.FAILED).count();

		ScanStatus status;
		if (scan.isCancelRequested()) {
			status = ScanStatus.CANCELLED;
		}
		else if (failed == 0 && completed == tasks.size()) {
			status = ScanStatus.COMPLETED;
		}
		else if (completed > 0) {
			status = ScanStatus.PARTIALLY_COMPLETED;
		}
		else {
			status = ScanStatus.FAILED;
		}

		scan.setStatus(status);
		scan.setFinishedAt(Instant.now());

		if (status == ScanStatus.FAILED) {
			scan.setErrorMessage("Все задачи завершились ошибкой");
		}

		scanRepository.save(scan);

		ScanEventType eventType = switch (status) {
			case COMPLETED, PARTIALLY_COMPLETED -> ScanEventType.SCAN_COMPLETED;
			case CANCELLED -> ScanEventType.SCAN_CANCELLED;
			default -> ScanEventType.SCAN_FAILED;
		};
		addEvent(scan, eventType, "Сканирование завершено со статусом " + status);
	}

	/**
	 * Таймаут одной задачи сканирования.
	 */
	public Duration getTaskTimeout() {
		return TASK_TIMEOUT;
	}

	private Scan getEntity(Long id) {
		return scanRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Сканирование не найдено: " + id));
	}

	private ScanTask getTask(Long taskId) {
		return scanTaskRepository.findById(taskId)
				.orElseThrow(() -> new ResourceNotFoundException("Задача сканирования не найдена: " + taskId));
	}

	private void addEvent(Scan scan, ScanEventType type, String message) {
		ScanEvent event = new ScanEvent();
		event.setScan(scan);
		event.setType(type);
		event.setMessage(message);
		scanEventRepository.save(event);
	}

}
