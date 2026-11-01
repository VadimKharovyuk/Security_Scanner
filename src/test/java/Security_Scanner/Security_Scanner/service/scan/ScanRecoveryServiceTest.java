package Security_Scanner.Security_Scanner.service.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import Security_Scanner.Security_Scanner.enums.ScanEventType;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanEvent;
import Security_Scanner.Security_Scanner.model.ScanTask;
import Security_Scanner.Security_Scanner.repository.ScanEventRepository;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.repository.ScanTaskRepository;

class ScanRecoveryServiceTest {

	private static final Long SCAN_ID = 1L;

	private final ScanRepository scanRepository = mock(ScanRepository.class);
	private final ScanTaskRepository scanTaskRepository = mock(ScanTaskRepository.class);
	private final ScanEventRepository scanEventRepository = mock(ScanEventRepository.class);

	private final ScanRecoveryService service =
			new ScanRecoveryService(scanRepository, scanTaskRepository, scanEventRepository);

	@Test
	void failsInterruptedScanAndClosesItsTasks() {
		Scan scan = scan(ScanStatus.RUNNING, false);
		ScanTask completed = task(ScanTaskStatus.COMPLETED);
		ScanTask running = task(ScanTaskStatus.RUNNING);
		ScanTask pending = task(ScanTaskStatus.PENDING);

		when(scanRepository.findByStatusIn(anyCollection())).thenReturn(List.of(scan));
		when(scanTaskRepository.findByScanIdOrderByIdAsc(SCAN_ID)).thenReturn(List.of(completed, running, pending));

		assertEquals(1, service.recoverInterrupted());

		assertEquals(ScanStatus.FAILED, scan.getStatus());
		assertEquals(ScanRecoveryService.RESTART_MESSAGE, scan.getErrorMessage());
		assertNotNull(scan.getFinishedAt());

		assertEquals(ScanTaskStatus.COMPLETED, completed.getStatus());
		assertNull(completed.getFinishedAt());

		assertEquals(ScanTaskStatus.FAILED, running.getStatus());
		assertEquals(ScanRecoveryService.RESTART_MESSAGE, running.getErrorMessage());
		assertNotNull(running.getFinishedAt());

		assertEquals(ScanTaskStatus.SKIPPED, pending.getStatus());
		assertNotNull(pending.getFinishedAt());

		assertEquals(ScanEventType.SCAN_FAILED, savedEvent().getType());
	}

	@Test
	void marksScanWithRequestedCancelAsCancelled() {
		Scan scan = scan(ScanStatus.RUNNING, true);

		when(scanRepository.findByStatusIn(anyCollection())).thenReturn(List.of(scan));
		when(scanTaskRepository.findByScanIdOrderByIdAsc(SCAN_ID)).thenReturn(List.of());

		service.recoverInterrupted();

		assertEquals(ScanStatus.CANCELLED, scan.getStatus());
		assertNull(scan.getErrorMessage());
		assertEquals(ScanEventType.SCAN_CANCELLED, savedEvent().getType());
	}

	@Test
	void reportsZeroWhenNothingIsInterrupted() {
		when(scanRepository.findByStatusIn(anyCollection())).thenReturn(List.of());

		assertEquals(0, service.recoverInterrupted());
		verify(scanEventRepository, never()).save(any());
	}

	@Test
	void abortFailsActiveScan() {
		Scan scan = scan(ScanStatus.QUEUED, false);

		when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));
		when(scanTaskRepository.findByScanIdOrderByIdAsc(SCAN_ID)).thenReturn(List.of());

		service.abort(SCAN_ID, ScanRecoveryService.QUEUE_FULL_MESSAGE);

		assertEquals(ScanStatus.FAILED, scan.getStatus());
		assertEquals(ScanRecoveryService.QUEUE_FULL_MESSAGE, scan.getErrorMessage());
	}

	@Test
	void abortKeepsFinishedScanUnchanged() {
		Scan scan = scan(ScanStatus.COMPLETED, false);

		when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.of(scan));

		service.abort(SCAN_ID, ScanRecoveryService.INTERNAL_ERROR_MESSAGE);

		assertEquals(ScanStatus.COMPLETED, scan.getStatus());
		assertNull(scan.getErrorMessage());
		verify(scanEventRepository, never()).save(any());
	}

	@Test
	void abortIgnoresDeletedScan() {
		when(scanRepository.findById(SCAN_ID)).thenReturn(Optional.empty());

		service.abort(SCAN_ID, ScanRecoveryService.INTERNAL_ERROR_MESSAGE);

		verify(scanEventRepository, never()).save(any());
	}

	private ScanEvent savedEvent() {
		ArgumentCaptor<ScanEvent> captor = ArgumentCaptor.forClass(ScanEvent.class);
		verify(scanEventRepository).save(captor.capture());
		return captor.getValue();
	}

	private Scan scan(ScanStatus status, boolean cancelRequested) {
		Scan scan = new Scan();
		scan.setId(SCAN_ID);
		scan.setStatus(status);
		scan.setCancelRequested(cancelRequested);
		return scan;
	}

	private ScanTask task(ScanTaskStatus status) {
		ScanTask task = new ScanTask();
		task.setStatus(status);
		return task;
	}

}
