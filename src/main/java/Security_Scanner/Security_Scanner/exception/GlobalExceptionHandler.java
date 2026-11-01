package Security_Scanner.Security_Scanner.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import lombok.extern.slf4j.Slf4j;

/**
 * Единый обработчик ошибок для MVC-страниц.
 */
@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(ResourceNotFoundException.class)
	public ModelAndView handleNotFound(ResourceNotFoundException exception) {
		return errorView(HttpStatus.NOT_FOUND, "Не найдено", exception.getMessage());
	}

	@ExceptionHandler(NoResourceFoundException.class)
	public ModelAndView handleNoResource(NoResourceFoundException exception) {
		return errorView(HttpStatus.NOT_FOUND, "Не найдено", "Страница не найдена");
	}

	@ExceptionHandler(ConflictException.class)
	public ModelAndView handleConflict(ConflictException exception) {
		return errorView(HttpStatus.CONFLICT, "Конфликт", exception.getMessage());
	}

	@ExceptionHandler(ScopeViolationException.class)
	public ModelAndView handleScopeViolation(ScopeViolationException exception) {
		return errorView(HttpStatus.BAD_REQUEST, "Недопустимый адрес", exception.getMessage());
	}

	@ExceptionHandler(AiUnavailableException.class)
	public ModelAndView handleAiUnavailable(AiUnavailableException exception) {
		return errorView(HttpStatus.SERVICE_UNAVAILABLE, "AI-анализ недоступен", exception.getMessage());
	}

	@ExceptionHandler(Exception.class)
	public ModelAndView handleUnexpected(Exception exception) {
		log.error("Необработанная ошибка", exception);
		return errorView(HttpStatus.INTERNAL_SERVER_ERROR, "Внутренняя ошибка", "Что-то пошло не так");
	}

	private ModelAndView errorView(HttpStatus status, String title, String message) {
		ModelAndView modelAndView = new ModelAndView("error");
		modelAndView.setStatus(status);
		modelAndView.addObject("status", status.value());
		modelAndView.addObject("title", title);
		modelAndView.addObject("message", message);
		return modelAndView;
	}

}
