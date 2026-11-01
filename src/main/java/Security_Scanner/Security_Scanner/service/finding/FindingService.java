package Security_Scanner.Security_Scanner.service.finding;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.finding.FindingResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.finding.ScanFindingSummary;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.mapper.FindingMapper;
import Security_Scanner.Security_Scanner.model.Finding;
import Security_Scanner.Security_Scanner.model.Scan;
import Security_Scanner.Security_Scanner.model.ScanFinding;
import Security_Scanner.Security_Scanner.model.SecurityEvidence;
import Security_Scanner.Security_Scanner.repository.FindingRepository;
import Security_Scanner.Security_Scanner.repository.ScanFindingRepository;
import Security_Scanner.Security_Scanner.repository.ScanRepository;
import Security_Scanner.Security_Scanner.repository.SecurityEvidenceRepository;
import Security_Scanner.Security_Scanner.service.scanner.EvidenceDraft;
import Security_Scanner.Security_Scanner.service.scanner.FindingDefinition;
import Security_Scanner.Security_Scanner.service.scanner.FindingDraft;
import lombok.RequiredArgsConstructor;

/**
 * Каталог находок и сохранение результатов сканеров.
 */
@Service
@RequiredArgsConstructor
public class FindingService {

	public static final int PAGE_SIZE = 20;

	private final FindingRepository findingRepository;
	private final ScanRepository scanRepository;
	private final ScanFindingRepository scanFindingRepository;
	private final SecurityEvidenceRepository evidenceRepository;
	private final FindingMapper findingMapper;

	@Transactional(readOnly = true)
	public List<ScanFindingResponse> findAll(int page) {
		Page<ScanFinding> result = scanFindingRepository
				.findAllByOrderByDetectedAtDesc(PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(this::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public List<ScanFindingResponse> findByScan(Long scanId) {
		return scanFindingRepository.findByScanIdOrderByDetectedAtDesc(scanId).stream()
				.map(this::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public ScanFindingResponse findById(Long id) {
		return toResponse(getEntity(id));
	}

	/**
	 * Находки сканирования с необязательными фильтрами. Значение null отключает фильтр.
	 */
	@Transactional(readOnly = true)
	public List<ScanFindingResponse> search(Long scanId, Severity severity, FindingStatus status) {
		assertScanExists(scanId);
		return scanFindingRepository.findByScanIdOrderByDetectedAtDesc(scanId).stream()
				.filter(finding -> severity == null || finding.getSeverity() == severity)
				.filter(finding -> status == null || finding.getStatus() == status)
				.map(this::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public ScanFindingSummary summarize(Long scanId) {
		assertScanExists(scanId);
		List<ScanFinding> findings = scanFindingRepository.findByScanIdOrderByDetectedAtDesc(scanId);

		Map<Severity, Long> bySeverity = new EnumMap<>(Severity.class);
		for (Severity severity : Severity.values()) {
			bySeverity.put(severity, 0L);
		}

		Map<FindingStatus, Long> byStatus = new EnumMap<>(FindingStatus.class);
		for (FindingStatus status : FindingStatus.values()) {
			byStatus.put(status, 0L);
		}

		for (ScanFinding finding : findings) {
			byStatus.merge(finding.getStatus(), 1L, Long::sum);
			if (finding.getStatus() != FindingStatus.FALSE_POSITIVE) {
				bySeverity.merge(finding.getSeverity(), 1L, Long::sum);
			}
		}

		return new ScanFindingSummary(scanId, findings.size(), bySeverity, byStatus);
	}

	/**
	 * Отмечает открытую находку как ложную.
	 * Статусы CONFIRMED и RESOLVED здесь недоступны: они требуют технической проверки.
	 */
	@Transactional
	public ScanFindingResponse markFalsePositive(Long id) {
		return changeStatus(id, FindingStatus.OPEN, FindingStatus.FALSE_POSITIVE);
	}

	@Transactional
	public ScanFindingResponse reopen(Long id) {
		return changeStatus(id, FindingStatus.FALSE_POSITIVE, FindingStatus.OPEN);
	}

	@Transactional(readOnly = true)
	public List<FindingResponse> findCatalog() {
		return findingRepository.findAll(Sort.by("code")).stream()
				.map(findingMapper::toResponse)
				.toList();
	}

	/**
	 * Сохраняет находки, обнаруженные сканером, вместе с доказательствами.
	 * Вызывается внутри транзакции завершения задачи.
	 */
	@Transactional
	public void record(Scan scan, List<FindingDraft> drafts) {
		for (FindingDraft draft : drafts) {
			Finding finding = resolve(draft.definition());

			ScanFinding scanFinding = new ScanFinding();
			scanFinding.setScan(scan);
			scanFinding.setFinding(finding);
			scanFinding.setStatus(FindingStatus.OPEN);
			scanFinding.setSeverity(draft.definition().severity());
			scanFinding.setConfidence(draft.definition().confidence());
			scanFinding.setUrl(draft.url());
			scanFinding.setDetectedAt(Instant.now());
			scanFinding = scanFindingRepository.save(scanFinding);

			for (EvidenceDraft draftEvidence : draft.evidence()) {
				SecurityEvidence evidence = new SecurityEvidence();
				evidence.setScanFinding(scanFinding);
				evidence.setType(draftEvidence.type());
				evidence.setContent(draftEvidence.content());
				evidence.setRequestSnippet(draftEvidence.requestSnippet());
				evidence.setResponseSnippet(draftEvidence.responseSnippet());
				evidenceRepository.save(evidence);
			}
		}
	}

	/**
	 * Синхронизирует каталог правил с определениями зарегистрированных сканеров.
	 */
	@Transactional
	public void syncCatalog(List<FindingDefinition> definitions) {
		for (FindingDefinition definition : definitions) {
			Finding finding = findingRepository.findByCode(definition.code())
					.orElseGet(Finding::new);
			apply(finding, definition);
			findingRepository.save(finding);
		}
	}

	@Transactional
	public void deleteByScan(Long scanId) {
		evidenceRepository.deleteByScanId(scanId);
		scanFindingRepository.deleteByScanId(scanId);
	}

	private ScanFindingResponse changeStatus(Long id, FindingStatus expected, FindingStatus target) {
		ScanFinding finding = getEntity(id);

		if (finding.getStatus() != expected) {
			throw new ConflictException("Нельзя перевести находку из статуса " + finding.getStatus() + " в " + target);
		}

		finding.setStatus(target);
		return toResponse(finding);
	}

	private void assertScanExists(Long scanId) {
		if (!scanRepository.existsById(scanId)) {
			throw new ResourceNotFoundException("Сканирование не найдено: " + scanId);
		}
	}

	private ScanFinding getEntity(Long id) {
		return scanFindingRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Находка не найдена: " + id));
	}

	private ScanFindingResponse toResponse(ScanFinding scanFinding) {
		return findingMapper.toResponse(
				scanFinding,
				evidenceRepository.findByScanFindingIdOrderByIdAsc(scanFinding.getId()));
	}

	private Finding resolve(FindingDefinition definition) {
		return findingRepository.findByCode(definition.code())
				.orElseGet(() -> {
					Finding finding = new Finding();
					apply(finding, definition);
					return findingRepository.save(finding);
				});
	}

	private void apply(Finding finding, FindingDefinition definition) {
		finding.setCode(definition.code());
		finding.setTitle(definition.title());
		finding.setDescription(definition.description());
		finding.setCategory(definition.category());
		finding.setSeverity(definition.severity());
		finding.setConfidence(definition.confidence());
		finding.setRecommendation(definition.recommendation());
		finding.setReference(definition.reference());
	}

}
