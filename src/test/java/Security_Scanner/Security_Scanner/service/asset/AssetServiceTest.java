package Security_Scanner.Security_Scanner.service.asset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.asset.AssetResponse;
import Security_Scanner.Security_Scanner.dto.project.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.project.ProjectResponse;
import Security_Scanner.Security_Scanner.enums.OwnershipStatus;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.service.project.ProjectService;

@SpringBootTest(properties = "security-scanner.scope.allowed-hosts=8.8.8.8")
@Transactional
class AssetServiceTest {

	@Autowired
	private ProjectService projectService;

	@Autowired
	private AssetService assetService;

	@Test
	void createsProjectAndAsset() {
		ProjectResponse project = createProject("WebCraft Production");

		AssetRequest request = new AssetRequest();
		request.setProjectId(project.id());
		request.setName("Public site");
		request.setBaseUrl("https://8.8.8.8/path?x=1#frag");

		AssetResponse asset = assetService.create(request);

		assertEquals("https://8.8.8.8/path", asset.baseUrl());
		assertEquals(project.id(), asset.projectId());
		assertEquals(OwnershipStatus.NOT_REQUIRED, asset.ownershipStatus());
	}

	@Test
	void rejectsDuplicateUrlInSameProject() {
		ProjectResponse project = createProject("Duplicates");

		assetService.create(assetRequest(project.id(), "https://8.8.8.8"));

		assertThrows(ConflictException.class,
				() -> assetService.create(assetRequest(project.id(), "https://8.8.8.8/")));
	}

	@Test
	void allowsSameUrlInDifferentProjects() {
		ProjectResponse first = createProject("First");
		ProjectResponse second = createProject("Second");

		assetService.create(assetRequest(first.id(), "https://8.8.8.8"));
		AssetResponse asset = assetService.create(assetRequest(second.id(), "https://8.8.8.8"));

		assertEquals(second.id(), asset.projectId());
	}

	@Test
	void forbidsDeletingProjectWithAssets() {
		ProjectResponse project = createProject("Not empty");
		assetService.create(assetRequest(project.id(), "https://8.8.8.8"));

		assertThrows(ConflictException.class, () -> projectService.delete(project.id()));
	}

	@Test
	void deactivateKeepsAssetInList() {
		ProjectResponse project = createProject("Deactivate");
		AssetResponse asset = assetService.create(assetRequest(project.id(), "https://8.8.8.8"));

		AssetResponse deactivated = assetService.deactivate(asset.id());

		assertFalse(deactivated.active());
		List<AssetResponse> assets = assetService.findByProject(project.id(), 0);
		assertEquals(1, assets.size());
	}

	@Test
	void deletesProjectWithoutAssets() {
		ProjectResponse project = createProject("Temporary");

		projectService.delete(project.id());

		assertThrows(Security_Scanner.Security_Scanner.exception.ResourceNotFoundException.class,
				() -> projectService.findById(project.id()));
	}

	private ProjectResponse createProject(String name) {
		ProjectRequest request = new ProjectRequest();
		request.setName(name);
		return projectService.create(request);
	}

	private AssetRequest assetRequest(Long projectId, String url) {
		AssetRequest request = new AssetRequest();
		request.setProjectId(projectId);
		request.setName("Asset");
		request.setBaseUrl(url);
		return request;
	}

}
