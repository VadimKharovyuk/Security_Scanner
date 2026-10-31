package Security_Scanner.Security_Scanner.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.Asset;

/**
 * Репозиторий активов.
 */
@Repository
public interface AssetRepository extends JpaRepository<Asset, Long> {

	List<Asset> findByProjectIdOrderByCreatedAtDesc(Long projectId);

	List<Asset> findByProjectIdAndActiveTrueOrderByCreatedAtDesc(Long projectId);

	Optional<Asset> findByIdAndProjectId(Long id, Long projectId);

	boolean existsByProjectIdAndBaseUrl(Long projectId, String baseUrl);

	long countByProjectId(Long projectId);

}
