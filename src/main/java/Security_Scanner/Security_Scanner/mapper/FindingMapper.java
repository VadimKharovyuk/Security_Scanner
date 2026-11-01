package Security_Scanner.Security_Scanner.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.dto.FindingResponse;
import Security_Scanner.Security_Scanner.dto.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.SecurityEvidenceResponse;
import Security_Scanner.Security_Scanner.model.Finding;
import Security_Scanner.Security_Scanner.model.ScanFinding;
import Security_Scanner.Security_Scanner.model.SecurityEvidence;

/**
 * Ручной маппер каталога находок и доказательств.
 */
@Component
public class FindingMapper {

	public FindingResponse toResponse(Finding finding) {
		return new FindingResponse(
				finding.getId(),
				finding.getCode(),
				finding.getTitle(),
				finding.getDescription(),
				finding.getCategory(),
				finding.getSeverity(),
				finding.getConfidence(),
				finding.getRecommendation(),
				finding.getReference()
		);
	}

	public ScanFindingResponse toResponse(ScanFinding scanFinding, List<SecurityEvidence> evidence) {
		Finding finding = scanFinding.getFinding();

		return new ScanFindingResponse(
				scanFinding.getId(),
				scanFinding.getScan().getId(),
				finding.getId(),
				finding.getCode(),
				finding.getTitle(),
				finding.getDescription(),
				finding.getCategory(),
				scanFinding.getStatus(),
				scanFinding.getSeverity(),
				scanFinding.getConfidence(),
				finding.getRecommendation(),
				finding.getReference(),
				scanFinding.getUrl(),
				scanFinding.getDetectedAt(),
				evidence.stream().map(this::toResponse).toList()
		);
	}

	public SecurityEvidenceResponse toResponse(SecurityEvidence evidence) {
		return new SecurityEvidenceResponse(
				evidence.getId(),
				evidence.getType(),
				evidence.getContent(),
				evidence.getRequestSnippet(),
				evidence.getResponseSnippet()
		);
	}

}
