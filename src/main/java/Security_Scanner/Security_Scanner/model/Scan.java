package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import Security_Scanner.Security_Scanner.enums.ScanStatus;
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
 * Запуск сканирования актива.
 */
@Entity
@Table(name = "scans")
@Getter
@Setter
@NoArgsConstructor
public class Scan {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "asset_id", nullable = false)
	private Asset asset;

	@Enumerated(EnumType.STRING)
	@Column(name = "status", nullable = false, length = 30)
	private ScanStatus status = ScanStatus.QUEUED;

	@Column(name = "cancel_requested", nullable = false)
	private boolean cancelRequested = false;

	@Column(name = "error_message", length = 1000)
	private String errorMessage;

	@Column(name = "started_at")
	private Instant startedAt;

	@Column(name = "finished_at")
	private Instant finishedAt;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@UpdateTimestamp
	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

}
