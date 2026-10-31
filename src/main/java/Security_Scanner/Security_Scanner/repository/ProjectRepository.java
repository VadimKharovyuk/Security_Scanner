package Security_Scanner.Security_Scanner.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.Project;

/**
 * Репозиторий проектов.
 */
@Repository
public interface ProjectRepository extends JpaRepository<Project, Long> {

	List<Project> findAllByOrderByCreatedAtDesc();

}
