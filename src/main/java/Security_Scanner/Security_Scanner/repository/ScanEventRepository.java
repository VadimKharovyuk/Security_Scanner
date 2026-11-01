package Security_Scanner.Security_Scanner.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.ScanEvent;

@Repository
public interface ScanEventRepository extends JpaRepository<ScanEvent, Long> {

	List<ScanEvent> findByScanIdOrderByCreatedAtAsc(Long scanId);

	void deleteByScanId(Long scanId);

}
