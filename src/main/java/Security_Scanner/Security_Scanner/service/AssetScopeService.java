package Security_Scanner.Security_Scanner.service;

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Service;

import Security_Scanner.Security_Scanner.config.ScanScopeProperties;
import Security_Scanner.Security_Scanner.exception.ScopeViolationException;
import lombok.RequiredArgsConstructor;

/**
 * Техническое ограничение области сканирования.
 * Проверяет формат URL, схему, разрешённые хосты и блокирует SSRF-цели.
 * Не подтверждает владение активом — это задача OwnershipVerifier.
 */
@Service
@RequiredArgsConstructor
public class AssetScopeService {

	private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

	private static final Set<String> BLOCKED_HOSTNAMES = Set.of(
			"localhost",
			"metadata",
			"metadata.google.internal"
	);

	private final ScanScopeProperties properties;

	/**
	 * Проверяет URL и возвращает нормализованный адрес без query и fragment.
	 *
	 * @throws ScopeViolationException если URL недопустим или вне разрешённой области
	 */
	public String validateAndNormalize(String rawUrl) {
		if (rawUrl == null || rawUrl.isBlank()) {
			throw new ScopeViolationException("URL не указан");
		}

		URI uri = parse(rawUrl);

		String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
		if (!ALLOWED_SCHEMES.contains(scheme)) {
			throw new ScopeViolationException("Разрешены только http и https");
		}

		if (uri.getHost() == null || uri.getHost().isBlank()) {
			throw new ScopeViolationException("URL должен содержать hostname");
		}

		if (uri.getUserInfo() != null) {
			throw new ScopeViolationException("URL не должен содержать учётные данные");
		}

		String host = normalizeHost(uri.getHost());

		if (BLOCKED_HOSTNAMES.contains(host)) {
			throw new ScopeViolationException("Хост запрещён: " + host);
		}

		if (!isHostAllowed(host)) {
			throw new ScopeViolationException("Хост вне разрешённой области: " + host);
		}

		resolveAndCheckAddresses(host);

		return buildNormalizedUrl(scheme, host, uri.getPort(), uri.getRawPath());
	}

	private URI parse(String rawUrl) {
		try {
			return new URI(rawUrl.trim());
		}
		catch (URISyntaxException e) {
			throw new ScopeViolationException("Некорректный URL");
		}
	}

	private String normalizeHost(String host) {
		String ascii = IDN.toASCII(host).toLowerCase(Locale.ROOT);
		if (ascii.endsWith(".")) {
			ascii = ascii.substring(0, ascii.length() - 1);
		}
		return ascii;
	}

	private boolean isHostAllowed(String host) {
		if (properties.getAllowedHosts().isEmpty()) {
			return false;
		}

		for (String rawAllowed : properties.getAllowedHosts()) {
			String allowed = normalizeHost(rawAllowed.trim());
			if (host.equals(allowed)) {
				return true;
			}
			if (properties.isAllowSubdomains() && host.endsWith("." + allowed)) {
				return true;
			}
		}

		return false;
	}

	private void resolveAndCheckAddresses(String host) {
		InetAddress[] addresses;
		try {
			addresses = InetAddress.getAllByName(host);
		}
		catch (UnknownHostException e) {
			throw new ScopeViolationException("Не удалось разрешить хост: " + host);
		}

		for (InetAddress address : addresses) {
			assertPublicAddress(host, address);
		}
	}

	private void assertPublicAddress(String host, InetAddress address) {
		if (address.isAnyLocalAddress()
				|| address.isLoopbackAddress()
				|| address.isLinkLocalAddress()
				|| address.isSiteLocalAddress()
				|| address.isMulticastAddress()) {
			throw new ScopeViolationException(
					"Хост " + host + " указывает на запрещённый адрес: " + address.getHostAddress());
		}

		byte[] bytes = address.getAddress();

		if (address instanceof Inet4Address && isBlockedIpv4(bytes)) {
			throw new ScopeViolationException(
					"Хост " + host + " указывает на запрещённый адрес: " + address.getHostAddress());
		}

		if (address instanceof Inet6Address && isUniqueLocalIpv6(bytes)) {
			throw new ScopeViolationException(
					"Хост " + host + " указывает на запрещённый адрес: " + address.getHostAddress());
		}
	}

	private boolean isBlockedIpv4(byte[] bytes) {
		int first = bytes[0] & 0xFF;
		int second = bytes[1] & 0xFF;

		// 0.0.0.0/8
		if (first == 0) {
			return true;
		}
		// 100.64.0.0/10 (CGNAT)
		if (first == 100 && second >= 64 && second <= 127) {
			return true;
		}
		// 192.0.0.0/24
		if (first == 192 && second == 0 && (bytes[2] & 0xFF) == 0) {
			return true;
		}
		// 198.18.0.0/15 (benchmark)
		if (first == 198 && (second == 18 || second == 19)) {
			return true;
		}
		// 240.0.0.0/4 (reserved)
		return first >= 240;
	}

	private boolean isUniqueLocalIpv6(byte[] bytes) {
		// fc00::/7
		return (bytes[0] & 0xFE) == 0xFC;
	}

	private String buildNormalizedUrl(String scheme, String host, int port, String rawPath) {
		boolean defaultPort = (scheme.equals("http") && port == 80)
				|| (scheme.equals("https") && port == 443);

		StringBuilder url = new StringBuilder(scheme).append("://").append(host);

		if (port != -1 && !defaultPort) {
			url.append(':').append(port);
		}

		// Корневой путь "/" и пустой путь считаем одним и тем же адресом.
		if (rawPath != null && !rawPath.isEmpty() && !rawPath.equals("/")) {
			url.append(rawPath);
		}

		return url.toString();
	}

}
