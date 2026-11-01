package Security_Scanner.Security_Scanner.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.SecurityEvidence;

@Repository
public interface SecurityEvidenceRepository extends JpaRepository<SecurityEvidence, Long> {

	List<SecurityEvidence> findByScanFindingIdOrderByIdAsc(Long scanFindingId);

	@Modifying
	@Query("delete from SecurityEvidence e where e.scanFinding.scan.id = :scanId")
	void deleteByScanId(@Param("scanId") Long scanId);

}
