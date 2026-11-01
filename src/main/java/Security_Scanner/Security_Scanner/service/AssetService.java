package Security_Scanner.Security_Scanner.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.asset.AssetResponse;
import Security_Scanner.Security_Scanner.dto.asset.OwnershipCheckResult;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.mapper.AssetMapper;
import Security_Scanner.Security_Scanner.model.Asset;
import Security_Scanner.Security_Scanner.model.Project;
import Security_Scanner.Security_Scanner.repository.AssetRepository;
import lombok.RequiredArgsConstructor;

/**
 * Бизнес-логика активов.
 * URL проверяется AssetScopeService, владение — OwnershipVerifier.
 */
@Service
@RequiredArgsConstructor
public class AssetService {

	public static final int PAGE_SIZE = 20;

	private final AssetRepository assetRepository;
	private final ProjectService projectService;
	private final AssetMapper assetMapper;
	private final AssetScopeService assetScopeService;
	private final OwnershipVerifier ownershipVerifier;

	@Transactional(readOnly = true)
	public List<AssetResponse> findAll(int page) {
		Page<Asset> result = assetRepository
				.findAllByOrderByCreatedAtDesc(PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(assetMapper::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public List<AssetResponse> findByProject(Long projectId, int page) {
		projectService.getEntity(projectId);
		Page<Asset> result = assetRepository
				.findByProjectIdOrderByCreatedAtDesc(projectId, PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(assetMapper::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public AssetResponse findById(Long id) {
		return assetMapper.toResponse(getEntity(id));
	}

	@Transactional(readOnly = true)
	public Asset getEntity(Long id) {
		return assetRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Актив не найден: " + id));
	}

	@Transactional
	public AssetResponse create(AssetRequest request) {
		Project project = projectService.getEntity(request.getProjectId());
		String normalizedUrl = assetScopeService.validateAndNormalize(request.getBaseUrl());

		if (assetRepository.existsByProjectIdAndBaseUrl(project.getId(), normalizedUrl)) {
			throw new ConflictException("Актив с таким URL уже существует в проекте");
		}

		Asset asset = assetMapper.toEntity(request, project);
		asset.setBaseUrl(normalizedUrl);
		applyOwnership(asset);

		return assetMapper.toResponse(assetRepository.save(asset));
	}

	@Transactional
	public AssetResponse update(Long id, AssetRequest request) {
		Asset asset = getEntity(id);
		String normalizedUrl = assetScopeService.validateAndNormalize(request.getBaseUrl());

		boolean urlChanged = !normalizedUrl.equals(asset.getBaseUrl());
		if (urlChanged && assetRepository.existsByProjectIdAndBaseUrl(asset.getProject().getId(), normalizedUrl)) {
			throw new ConflictException("Актив с таким URL уже существует в проекте");
		}

		assetMapper.updateEntity(asset, request);
		asset.setBaseUrl(normalizedUrl);
		applyOwnership(asset);

		return assetMapper.toResponse(assetRepository.save(asset));
	}

	/**
	 * Мягкое удаление: актив перестаёт участвовать в сканированиях, история сохраняется.
	 */
	@Transactional
	public AssetResponse deactivate(Long id) {
		Asset asset = getEntity(id);
		asset.setActive(false);
		return assetMapper.toResponse(assetRepository.save(asset));
	}

	@Transactional
	public void delete(Long id) {
		assetRepository.delete(getEntity(id));
	}

	private void applyOwnership(Asset asset) {
		OwnershipCheckResult result = ownershipVerifier.verify(asset);
		asset.setOwnershipStatus(result.status());
		asset.setOwnershipCheckedAt(result.checkedAt());
	}

}
