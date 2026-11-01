package Security_Scanner.Security_Scanner.repository;

import java.util.Collection;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.enums.ScanStatus;
import Security_Scanner.Security_Scanner.model.Scan;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

	Page<Scan> findAllByOrderByCreatedAtDesc(Pageable pageable);

	Page<Scan> findByAssetIdOrderByCreatedAtDesc(Long assetId, Pageable pageable);

	List<Scan> findByStatusIn(Collection<ScanStatus> statuses);

}
