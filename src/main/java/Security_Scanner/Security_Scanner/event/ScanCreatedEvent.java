package Security_Scanner.Security_Scanner.event;

/**
 * Событие: сканирование создано и готово к запуску.
 * Публикуется внутри транзакции, обрабатывается после её коммита.
 */
public record ScanCreatedEvent(Long scanId) {
}
