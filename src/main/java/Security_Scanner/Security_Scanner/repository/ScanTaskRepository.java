package Security_Scanner.Security_Scanner.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.ScanTask;

@Repository
public interface ScanTaskRepository extends JpaRepository<ScanTask, Long> {

	List<ScanTask> findByScanIdOrderByIdAsc(Long scanId);

	void deleteByScanId(Long scanId);

}
