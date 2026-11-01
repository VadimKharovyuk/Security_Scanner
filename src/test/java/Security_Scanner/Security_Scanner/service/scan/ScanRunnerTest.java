package Security_Scanner.Security_Scanner.service.scan;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskExecutor;
import org.springframework.core.task.TaskRejectedException;

import Security_Scanner.Security_Scanner.event.ScanCreatedEvent;

class ScanRunnerTest {

	private static final Long SCAN_ID = 1L;

	private final ScanOrchestrator orchestrator = mock(ScanOrchestrator.class);
	private final ScanRecoveryService recoveryService = mock(ScanRecoveryService.class);
	private final TaskExecutor executor = mock(TaskExecutor.class);

	private final ScanRunner runner = new ScanRunner(orchestrator, recoveryService, List.of(), executor);

	@Test
	void abortsScanRejectedByExecutor() {
		doThrow(new TaskRejectedException("Очередь заполнена")).when(executor).execute(any());

		runner.onScanCreated(new ScanCreatedEvent(SCAN_ID));

		verify(recoveryService).abort(SCAN_ID, ScanRecoveryService.QUEUE_FULL_MESSAGE);
	}

	@Test
	void abortsScanWhenRunFailsOutsideTask() {
		when(orchestrator.prepareRun(SCAN_ID)).thenThrow(new IllegalStateException("БД недоступна"));

		runner.execute(SCAN_ID);

		verify(recoveryService).abort(SCAN_ID, ScanRecoveryService.INTERNAL_ERROR_MESSAGE);
	}

	@Test
	void abortsScanWhenFinishFails() {
		when(orchestrator.prepareRun(SCAN_ID))
				.thenReturn(new ScanOrchestrator.RunData(SCAN_ID, 2L, "https://example.com", List.of()));
		doThrow(new IllegalStateException("БД недоступна")).when(orchestrator).finish(SCAN_ID);

		runner.execute(SCAN_ID);

		verify(recoveryService).abort(SCAN_ID, ScanRecoveryService.INTERNAL_ERROR_MESSAGE);
	}

	@Test
	void doesNotAbortSuccessfulRun() {
		when(orchestrator.prepareRun(SCAN_ID))
				.thenReturn(new ScanOrchestrator.RunData(SCAN_ID, 2L, "https://example.com", List.of()));

		runner.execute(SCAN_ID);

		verify(orchestrator).finish(SCAN_ID);
		verify(recoveryService, never()).abort(any(), any());
	}

}
