package Security_Scanner.Security_Scanner.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.dto.scanevent.ScanEventResponse;
import Security_Scanner.Security_Scanner.dto.scan.ScanResponse;
import Security_Scanner.Security_Scanner.dto.scantask.ScanTaskResponse;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanEvent;
import Security_Scanner.Security_Scanner.model.ScanTask;

/**
 * Ручной маппер сканирований.
 */
@Component
public class ScanMapper {

	public ScanResponse toResponse(Scan scan, List<ScanTask> tasks, List<ScanEvent> events) {
		return new ScanResponse(
				scan.getId(),
				scan.getAsset().getId(),
				scan.getStatus(),
				scan.isCancelRequested(),
				scan.getErrorMessage(),
				scan.getCreatedAt(),
				scan.getStartedAt(),
				scan.getFinishedAt(),
				tasks.stream().map(this::toTaskResponse).toList(),
				events.stream().map(this::toEventResponse).toList()
		);
	}

	public ScanTaskResponse toTaskResponse(ScanTask task) {
		return new ScanTaskResponse(
				task.getId(),
				task.getScannerType(),
				task.getStatus(),
				task.getErrorMessage(),
				task.getStartedAt(),
				task.getFinishedAt()
		);
	}

	public ScanEventResponse toEventResponse(ScanEvent event) {
		return new ScanEventResponse(
				event.getId(),
				event.getType(),
				event.getMessage(),
				event.getCreatedAt()
		);
	}

}
