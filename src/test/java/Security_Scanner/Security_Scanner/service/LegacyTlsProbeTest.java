package Security_Scanner.Security_Scanner.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;

class LegacyTlsProbeTest {

	@Test
	void clientHelloHasConsistentLengthsAndRequestedVersion() {
		byte[] hello = LegacyTlsProbe.clientHello("example.com", LegacyTlsProbe.Version.TLS_1_1);

		assertEquals(0x16, hello[0]);
		assertEquals(hello.length - 5, ((hello[3] & 0xFF) << 8) | (hello[4] & 0xFF));
		assertEquals(0x01, hello[5]);
		assertEquals(hello.length - 9,
				((hello[6] & 0xFF) << 16) | ((hello[7] & 0xFF) << 8) | (hello[8] & 0xFF));
		assertEquals(0x03, hello[9]);
		assertEquals(0x02, hello[10]);
	}

	@Test
	void clientHelloSendsSniOnlyForHostnames() {
		assertTrue(asText(LegacyTlsProbe.clientHello("example.com", LegacyTlsProbe.Version.TLS_1_0))
				.contains("example.com"));
		assertFalse(asText(LegacyTlsProbe.clientHello("8.8.8.8", LegacyTlsProbe.Version.TLS_1_0))
				.contains("8.8.8.8"));
	}

	@Test
	void acceptsServerHelloWithRequestedVersion() throws IOException {
		assertTrue(LegacyTlsProbe.isServerHello(
				new ByteArrayInputStream(serverHello(0x01)), LegacyTlsProbe.Version.TLS_1_0));
	}

	@Test
	void rejectsServerHelloWithOtherVersion() throws IOException {
		assertFalse(LegacyTlsProbe.isServerHello(
				new ByteArrayInputStream(serverHello(0x03)), LegacyTlsProbe.Version.TLS_1_0));
	}

	@Test
	void rejectsAlert() throws IOException {
		byte[] alert = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46 };

		assertFalse(LegacyTlsProbe.isServerHello(
				new ByteArrayInputStream(alert), LegacyTlsProbe.Version.TLS_1_0));
	}

	@Test
	void rejectsNonTlsResponse() throws IOException {
		byte[] http = "HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

		assertFalse(LegacyTlsProbe.isServerHello(
				new ByteArrayInputStream(http), LegacyTlsProbe.Version.TLS_1_0));
	}

	@Test
	void reportsClosedConnectionAsError() {
		assertThrows(EOFException.class, () -> LegacyTlsProbe.isServerHello(
				new ByteArrayInputStream(new byte[0]), LegacyTlsProbe.Version.TLS_1_0));
	}

	@Test
	void probesServerOverSocket() throws Exception {
		try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			Thread thread = new Thread(() -> {
				try (Socket client = server.accept()) {
					client.getInputStream().read(new byte[1024]);
					client.getOutputStream().write(serverHello(0x02));
				}
				catch (IOException exception) {
					throw new IllegalStateException(exception);
				}
			});
			thread.start();

			assertTrue(LegacyTlsProbe.accepts(
					server.getInetAddress().getHostAddress(),
					server.getLocalPort(),
					LegacyTlsProbe.Version.TLS_1_1,
					Duration.ofSeconds(5)));

			thread.join();
		}
	}

	private String asText(byte[] bytes) {
		return new String(bytes, StandardCharsets.ISO_8859_1);
	}

	private byte[] serverHello(int minor) {
		return new byte[] { 0x16, 0x03, 0x01, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0x03, (byte) minor };
	}

}
