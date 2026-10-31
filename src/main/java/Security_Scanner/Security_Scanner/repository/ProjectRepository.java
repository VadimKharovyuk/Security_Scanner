package Security_Scanner.Security_Scanner.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.Project;

/**
 * Репозиторий проектов.
 */
@Repository
public interface ProjectRepository extends JpaRepository<Project, Long> {

	Page<Project> findAllByOrderByCreatedAtDesc(Pageable pageable);

}
