package Security_Scanner.Security_Scanner.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import Security_Scanner.Security_Scanner.model.Finding;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {

	Optional<Finding> findByCode(String code);

}
