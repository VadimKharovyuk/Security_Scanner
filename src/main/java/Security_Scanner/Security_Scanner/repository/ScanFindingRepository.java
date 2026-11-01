package Security_Scanner.Security_Scanner.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.ScanFinding;

@Repository
public interface ScanFindingRepository extends JpaRepository<ScanFinding, Long> {

	List<ScanFinding> findByScanIdOrderByDetectedAtDesc(Long scanId);

	Page<ScanFinding> findAllByOrderByDetectedAtDesc(Pageable pageable);

	@Modifying
	@Query("delete from ScanFinding f where f.scan.id = :scanId")
	void deleteByScanId(@Param("scanId") Long scanId);

}
