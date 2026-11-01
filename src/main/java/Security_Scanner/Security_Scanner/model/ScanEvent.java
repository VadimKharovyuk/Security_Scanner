package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import Security_Scanner.Security_Scanner.enums.ScanEventType;
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
 * Событие сканирования: прогресс, смена статусов, ошибки.
 */
@Entity
@Table(name = "scan_events")
@Getter
@Setter
@NoArgsConstructor
public class ScanEvent {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "scan_id", nullable = false)
	private Scan scan;

	@Enumerated(EnumType.STRING)
	@Column(name = "type", nullable = false, length = 40)
	private ScanEventType type;

	@Column(name = "message", length = 1000)
	private String message;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

}
