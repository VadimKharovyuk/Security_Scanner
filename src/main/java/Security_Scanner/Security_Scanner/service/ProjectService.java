package Security_Scanner.Security_Scanner.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import Security_Scanner.Security_Scanner.dto.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.ProjectResponse;
import Security_Scanner.Security_Scanner.exception.ConflictException;
import Security_Scanner.Security_Scanner.exception.ResourceNotFoundException;
import Security_Scanner.Security_Scanner.mapper.ProjectMapper;
import Security_Scanner.Security_Scanner.model.Project;
import Security_Scanner.Security_Scanner.repository.AssetRepository;
import Security_Scanner.Security_Scanner.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;

/**
 * Бизнес-логика проектов.
 */
@Service
@RequiredArgsConstructor
public class ProjectService {

	public static final int PAGE_SIZE = 20;

	private final ProjectRepository projectRepository;
	private final AssetRepository assetRepository;
	private final ProjectMapper projectMapper;

	@Transactional(readOnly = true)
	public List<ProjectResponse> findAll(int page) {
		Page<Project> result = projectRepository
				.findAllByOrderByCreatedAtDesc(PageRequest.of(Math.max(page, 0), PAGE_SIZE));
		return result.getContent().stream()
				.map(projectMapper::toResponse)
				.toList();
	}

	@Transactional(readOnly = true)
	public ProjectResponse findById(Long id) {
		return projectMapper.toResponse(getEntity(id));
	}

	/**
	 * Возвращает сущность проекта для внутреннего использования другими сервисами.
	 */
	@Transactional(readOnly = true)
	public Project getEntity(Long id) {
		return projectRepository.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Проект не найден: " + id));
	}

	@Transactional
	public ProjectResponse create(ProjectRequest request) {
		Project project = projectMapper.toEntity(request);
		return projectMapper.toResponse(projectRepository.save(project));
	}

	@Transactional
	public ProjectResponse update(Long id, ProjectRequest request) {
		Project project = getEntity(id);
		projectMapper.updateEntity(project, request);
		return projectMapper.toResponse(projectRepository.save(project));
	}

	@Transactional
	public void delete(Long id) {
		Project project = getEntity(id);

		if (assetRepository.countByProjectId(id) > 0) {
			throw new ConflictException("Нельзя удалить проект: в нём есть активы");
		}

		projectRepository.delete(project);
	}

}
