package Security_Scanner.Security_Scanner.mapper;

import org.springframework.stereotype.Component;

import Security_Scanner.Security_Scanner.dto.project.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.project.ProjectResponse;
import Security_Scanner.Security_Scanner.model.Project;

/**
 * Ручной маппер между Project и DTO.
 */
@Component
public class ProjectMapper {

	public Project toEntity(ProjectRequest request) {
		Project project = new Project();
		applyRequest(project, request);
		return project;
	}

	public void updateEntity(Project project, ProjectRequest request) {
		applyRequest(project, request);
	}

	public ProjectResponse toResponse(Project project) {
		return new ProjectResponse(
				project.getId(),
				project.getName(),
				project.getDescription(),
				project.getCreatedAt(),
				project.getUpdatedAt()
		);
	}

	private void applyRequest(Project project, ProjectRequest request) {
		project.setName(request.getName());
		project.setDescription(request.getDescription());
	}

}
