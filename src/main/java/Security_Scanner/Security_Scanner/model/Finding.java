package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import Security_Scanner.Security_Scanner.enums.Confidence;
import Security_Scanner.Security_Scanner.enums.FindingCategory;
import Security_Scanner.Security_Scanner.enums.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Каталог типов находок (правило проверки).
 * Один Finding описывает класс проблемы и может встречаться во многих сканированиях.
 */
@Entity
@Table(name = "findings",
		uniqueConstraints = @UniqueConstraint(name = "uk_findings_code", columnNames = "code"))
@Getter
@Setter
@NoArgsConstructor
public class Finding {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "code", nullable = false, length = 100)
	private String code;

	@Column(name = "title", nullable = false, length = 300)
	private String title;

	@Column(name = "description", length = 2000)
	private String description;

	@Enumerated(EnumType.STRING)
	@Column(name = "category", nullable = false, length = 40)
	private FindingCategory category;

	@Enumerated(EnumType.STRING)
	@Column(name = "severity", nullable = false, length = 20)
	private Severity severity;

	@Enumerated(EnumType.STRING)
	@Column(name = "confidence", nullable = false, length = 20)
	private Confidence confidence;

	@Column(name = "recommendation", length = 2000)
	private String recommendation;

	@Column(name = "reference", length = 2000)
	private String reference;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@UpdateTimestamp
	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

}
