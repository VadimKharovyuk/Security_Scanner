package Security_Scanner.Security_Scanner.model;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

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

import Security_Scanner.Security_Scanner.enums.OwnershipStatus;

/**
 * Актив — конкретная цель сканирования (URL), принадлежащая проекту.
 * Область сканирования проверяется AssetScopeService.
 */
@Entity
@Table(name = "assets")
@Getter
@Setter
@NoArgsConstructor
public class Asset {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "project_id", nullable = false)
	private Project project;

	@Column(name = "name", nullable = false, length = 150)
	private String name;

	@Column(name = "base_url", nullable = false, length = 2048)
	private String baseUrl;

	@Column(name = "active", nullable = false)
	private boolean active = true;

	@Enumerated(EnumType.STRING)
	@Column(name = "ownership_status", nullable = false, length = 30)
	private OwnershipStatus ownershipStatus = OwnershipStatus.NOT_REQUIRED;

	@Column(name = "ownership_checked_at")
	private Instant ownershipCheckedAt;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private Instant createdAt;

	@UpdateTimestamp
	@Column(name = "updated_at", nullable = false)
	private Instant updatedAt;

}
