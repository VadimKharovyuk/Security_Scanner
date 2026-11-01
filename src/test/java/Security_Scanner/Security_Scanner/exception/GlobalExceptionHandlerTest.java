package Security_Scanner.Security_Scanner.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

class GlobalExceptionHandlerTest {

	private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

	@Test
	void missingStaticResourceIsNotFound() {
		ModelAndView view = handler.handleNoResource(
				new NoResourceFoundException(HttpMethod.GET, "/favicon.ico", "favicon.ico"));

		assertEquals(HttpStatus.NOT_FOUND, view.getStatus());
		assertEquals("error", view.getViewName());
	}

}
