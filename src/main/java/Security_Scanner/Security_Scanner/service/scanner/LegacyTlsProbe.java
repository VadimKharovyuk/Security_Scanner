package Security_Scanner.Security_Scanner.service.scanner;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;

/**
 * Проверяет, принимает ли сервер TLS 1.0 или TLS 1.1.
 * JDK запрещает эти версии через jdk.tls.disabledAlgorithms, поэтому ClientHello формируется вручную.
 * Рукопожатие не завершается: достаточно версии, выбранной сервером в ServerHello.
 */
final class LegacyTlsProbe {

	enum Version {

		TLS_1_1("TLSv1.1", 0x02),
		TLS_1_0("TLSv1", 0x01);

		private final String protocol;
		private final int minor;

		Version(String protocol, int minor) {
			this.protocol = protocol;
			this.minor = minor;
		}

		String protocol() {
			return protocol;
		}

	}

	private static final int CONTENT_TYPE_HANDSHAKE = 0x16;

	private static final int HANDSHAKE_CLIENT_HELLO = 0x01;

	private static final int HANDSHAKE_SERVER_HELLO = 0x02;

	private static final int TLS_MAJOR_VERSION = 0x03;

	private static final int MIN_SERVER_HELLO_FRAGMENT = 6;

	private static final int[] CIPHER_SUITES = {
			0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
			0x000A  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	};

	private static final int[] SUPPORTED_GROUPS = {
			0x001D, // x25519
			0x0017, // secp256r1
			0x0018  // secp384r1
	};

	private static final SecureRandom RANDOM = new SecureRandom();

	private LegacyTlsProbe() {
	}

	/**
	 * @throws IOException если соединение не установлено или сервер закрыл его без ответа
	 */
	static boolean accepts(String host, int port, Version version, Duration timeout) throws IOException {
		try (Socket socket = new Socket()) {
			int timeoutMillis = (int) Math.min(timeout.toMillis(), Integer.MAX_VALUE);

			socket.connect(new InetSocketAddress(host, port), timeoutMillis);
			socket.setSoTimeout(timeoutMillis);

			socket.getOutputStream().write(clientHello(host, version));
			socket.getOutputStream().flush();

			return isServerHello(socket.getInputStream(), version);
		}
	}

	static byte[] clientHello(String host, Version version) {
		byte[] extensions = extensions(host);

		ByteBuffer body = ByteBuffer.allocate(
				2 + 32 + 1 + 2 + CIPHER_SUITES.length * 2 + 2 + 2 + extensions.length);
		body.put((byte) TLS_MAJOR_VERSION).put((byte) version.minor);

		byte[] random = new byte[32];
		RANDOM.nextBytes(random);
		body.put(random);

		// Пустой session_id
		body.put((byte) 0);

		body.putShort((short) (CIPHER_SUITES.length * 2));
		for (int suite : CIPHER_SUITES) {
			body.putShort((short) suite);
		}

		// Только null-сжатие
		body.put((byte) 1).put((byte) 0);

		body.putShort((short) extensions.length);
		body.put(extensions);

		int bodyLength = body.position();

		ByteBuffer record = ByteBuffer.allocate(5 + 4 + bodyLength);
		// Версия записи 3.1 — общепринятое значение для ClientHello.
		record.put((byte) CONTENT_TYPE_HANDSHAKE).put((byte) TLS_MAJOR_VERSION).put((byte) 0x01);
		record.putShort((short) (4 + bodyLength));
		record.put((byte) HANDSHAKE_CLIENT_HELLO);
		record.put((byte) (bodyLength >> 16)).put((byte) (bodyLength >> 8)).put((byte) bodyLength);
		record.put(body.array(), 0, bodyLength);

		return record.array();
	}

	/**
	 * Читает только начало первой записи. Alert и ответы другой версии означают, что версия не принята.
	 */
	static boolean isServerHello(InputStream stream, Version version) throws IOException {
		DataInputStream input = new DataInputStream(stream);

		int contentType = input.readUnsignedByte();
		input.skipNBytes(2);
		int fragmentLength = input.readUnsignedShort();

		if (contentType != CONTENT_TYPE_HANDSHAKE || fragmentLength < MIN_SERVER_HELLO_FRAGMENT) {
			return false;
		}

		int handshakeType = input.readUnsignedByte();
		input.skipNBytes(3);
		int major = input.readUnsignedByte();
		int minor = input.readUnsignedByte();

		return handshakeType == HANDSHAKE_SERVER_HELLO
				&& major == TLS_MAJOR_VERSION
				&& minor == version.minor;
	}

	private static byte[] extensions(String host) {
		// SNI не допускает IP-адреса.
		byte[] name = isIpLiteral(host) ? new byte[0] : host.getBytes(StandardCharsets.US_ASCII);
		int sniLength = name.length == 0 ? 0 : 4 + 2 + 1 + 2 + name.length;

		ByteBuffer buffer = ByteBuffer.allocate(
				sniLength + 4 + 2 + SUPPORTED_GROUPS.length * 2 + 4 + 2);

		if (name.length > 0) {
			buffer.putShort((short) 0x0000);
			buffer.putShort((short) (2 + 1 + 2 + name.length));
			buffer.putShort((short) (1 + 2 + name.length));
			buffer.put((byte) 0);
			buffer.putShort((short) name.length);
			buffer.put(name);
		}

		// supported_groups
		buffer.putShort((short) 0x000A);
		buffer.putShort((short) (2 + SUPPORTED_GROUPS.length * 2));
		buffer.putShort((short) (SUPPORTED_GROUPS.length * 2));
		for (int group : SUPPORTED_GROUPS) {
			buffer.putShort((short) group);
		}

		// ec_point_formats: uncompressed
		buffer.putShort((short) 0x000B);
		buffer.putShort((short) 2);
		buffer.put((byte) 1).put((byte) 0);

		return buffer.array();
	}

	private static boolean isIpLiteral(String host) {
		return host.contains(":") || host.matches("[0-9.]+");
	}

}
