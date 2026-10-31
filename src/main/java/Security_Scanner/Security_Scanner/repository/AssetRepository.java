package Security_Scanner.Security_Scanner.repository;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.Asset;

/**
 * Репозиторий активов.
 */
@Repository
public interface AssetRepository extends JpaRepository<Asset, Long> {

	Page<Asset> findAllByOrderByCreatedAtDesc(Pageable pageable);

	Page<Asset> findByProjectIdOrderByCreatedAtDesc(Long projectId, Pageable pageable);

	Page<Asset> findByProjectIdAndActiveTrueOrderByCreatedAtDesc(Long projectId, Pageable pageable);

	Optional<Asset> findByIdAndProjectId(Long id, Long projectId);

	boolean existsByProjectIdAndBaseUrl(Long projectId, String baseUrl);

	long countByProjectId(Long projectId);

}
