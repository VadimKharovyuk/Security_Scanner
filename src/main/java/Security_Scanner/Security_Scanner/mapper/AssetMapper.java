package Security_Scanner.Security_Scanner.mapper;

import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.dto.AssetRequest;
import Security_Scanner.Security_Scanner.dto.AssetResponse;
import Security_Scanner.Security_Scanner.model.Asset;
import Security_Scanner.Security_Scanner.model.Project;

/**
 * Ручной маппер между Asset и DTO.
 */
@Component
public class AssetMapper {

	public Asset toEntity(AssetRequest request, Project project) {
		Asset asset = new Asset();
		asset.setProject(project);
		applyRequest(asset, request);
		return asset;
	}

	public void updateEntity(Asset asset, AssetRequest request) {
		applyRequest(asset, request);
	}

	public AssetResponse toResponse(Asset asset) {
		return new AssetResponse(
				asset.getId(),
				asset.getProject().getId(),
				asset.getName(),
				asset.getBaseUrl(),
				asset.isActive(),
				asset.getCreatedAt(),
				asset.getUpdatedAt()
		);
	}

	private void applyRequest(Asset asset, AssetRequest request) {
		asset.setName(request.getName());
		asset.setBaseUrl(request.getBaseUrl());
	}

}
