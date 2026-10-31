package Security_Scanner.Security_Scanner.enums;

/**
 * Статус подтверждения владения активом.
 * В MVP проверка отключена, поэтому используется NOT_REQUIRED.
 */
public enum OwnershipStatus {

	NOT_REQUIRED("Проверка владения доменом отключена"),
	PENDING("Токен выдан, ожидается подтверждение"),
	VERIFIED("Владение доменом подтверждено"),
	FAILED("Проверка владения не пройдена"),
	EXPIRED("Срок действия токена истёк");

	private final String name;

	OwnershipStatus(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

}
