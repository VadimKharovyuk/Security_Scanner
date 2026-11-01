package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingStatus;
import Security_Scanner.Security_Scanner.enums.Severity;
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
 * Факт обнаружения находки в конкретном сканировании.
 * Severity и confidence могут отличаться от каталога — например, при ручном уточнении.
 */
@Entity
@Table(name = "scan_findings")
@Getter
@Setter
@NoArgsConstructor
public class ScanFinding {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "scan_id", nullable = false)
	private Scan scan;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "finding_id", nullable = false)
	private Finding finding;

	@Enumerated(EnumType.STRING)
	@Column(name = "status", nullable = false, length = 30)
	private FindingStatus status = FindingStatus.OPEN;

	@Enumerated(EnumType.STRING)
	@Column(name = "severity", nullable = false, length = 20)
	private Severity severity;

	@Enumerated(EnumType.STRING)
	@Column(name = "confidence", nullable = false, length = 20)
	private Confidence confidence;

	@Column(name = "url", nullable = false, length = 2048)
	private String url;

	@Column(name = "detected_at", nullable = false)
	private Instant detectedAt;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

}
