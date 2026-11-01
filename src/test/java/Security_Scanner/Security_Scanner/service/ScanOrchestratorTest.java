package Security_Scanner.Security_Scanner.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.asset.AssetResponse;
import Security_Scanner.Security_Scanner.dto.project.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.project.ProjectResponse;
import Security_Scanner.Security_Scanner.dto.scan.ScanRequest;
import Security_Scanner.Security_Scanner.dto.scan.ScanResponse;
import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.enums.ScanTaskStatus;
import Security_Scanner.Security_Scanner.repository.ScanEventRepository;

@SpringBootTest(properties = {
		"security-scanner.scope.allowed-hosts=8.8.8.8",
		"security-scanner.stub.enabled=true",
		"security-scanner.http.enabled=false",
		"security-scanner.tls.enabled=false"
})
class ScanOrchestratorTest {

	@Autowired
	private ProjectService projectService;

	@Autowired
	private AssetService assetService;

	@Autowired
	private ScanOrchestrator orchestrator;

	@Autowired
	private ScanEventRepository scanEventRepository;

	@Test
	void runsScanLifecycleWithStubScanner() throws InterruptedException {
		ProjectResponse project = createProject();
		AssetResponse asset = createAsset(project.id());

		ScanResponse created = orchestrator.create(scanRequest(asset.id()));
		assertEquals(ScanStatus.QUEUED, created.status());
		assertFalse(created.tasks().isEmpty());

		try {
			ScanResponse finished = awaitTerminal(created.id(), Duration.ofSeconds(10));

			assertEquals(ScanStatus.COMPLETED, finished.status());
			assertTrue(finished.tasks().stream()
					.allMatch(task -> task.status() == ScanTaskStatus.COMPLETED));
			assertFalse(scanEventRepository.findByScanIdOrderByCreatedAtAsc(created.id()).isEmpty());
		}
		finally {
			orchestrator.delete(created.id());
			assetService.delete(asset.id());
			projectService.delete(project.id());
		}
	}

	private ScanResponse awaitTerminal(Long scanId, Duration timeout) throws InterruptedException {
		Instant deadline = Instant.now().plus(timeout);

		while (Instant.now().isBefore(deadline)) {
			ScanResponse scan = orchestrator.findById(scanId);

			if (scan.status() == ScanStatus.COMPLETED
					|| scan.status() == ScanStatus.PARTIALLY_COMPLETED
					|| scan.status() == ScanStatus.FAILED
					|| scan.status() == ScanStatus.CANCELLED) {
				return scan;
			}

			Thread.sleep(50);
		}

		fail("Сканирование не завершилось за " + timeout);
		return null;
	}

	private ProjectResponse createProject() {
		ProjectRequest request = new ProjectRequest();
		request.setName("Scan test " + System.nanoTime());
		return projectService.create(request);
	}

	private AssetResponse createAsset(Long projectId) {
		AssetRequest request = new AssetRequest();
		request.setProjectId(projectId);
		request.setName("Scan target");
		request.setBaseUrl("https://8.8.8.8");
		return assetService.create(request);
	}

	private ScanRequest scanRequest(Long assetId) {
		ScanRequest request = new ScanRequest();
		request.setAssetId(assetId);
		return request;
	}

}
