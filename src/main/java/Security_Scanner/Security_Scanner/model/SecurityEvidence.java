package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import Security_Scanner.Security_Scanner.enums.EvidenceType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Техническое доказательство находки: заголовок, фрагмент ответа, параметры запроса.
 * Секреты и персональные данные должны редактироваться до сохранения.
 */
@Entity
@Table(name = "security_evidence")
@Getter
@Setter
@NoArgsConstructor
public class SecurityEvidence {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "scan_finding_id", nullable = false)
	private ScanFinding scanFinding;

	@Enumerated(EnumType.STRING)
	@Column(name = "type", nullable = false, length = 40)
	private EvidenceType type;

	@Column(name = "content", length = 4000)
	private String content;

	@Column(name = "request_snippet", length = 2000)
	private String requestSnippet;

	@Column(name = "response_snippet", length = 2000)
	private String responseSnippet;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

}
