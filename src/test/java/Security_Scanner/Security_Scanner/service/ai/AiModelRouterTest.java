package Security_Scanner.Security_Scanner.service.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import Security_Scanner.Security_Scanner.config.OpenRouterProperties;
import Security_Scanner.Security_Scanner.enums.AiTaskType;

class AiModelRouterTest {

	private final OpenRouterProperties properties = new OpenRouterProperties();

	private final AiModelRouter router = new AiModelRouter(properties);

	@BeforeEach
	void setUp() {
		properties.setModel("default-model");
		properties.setTemperature(0.3);
		properties.setMaxTokens(8192);
	}

	@Test
	void usesDefaultsForTaskWithoutOverride() {
		assertEquals(new AiModelRouter.ModelSettings("default-model", 0.3, 8192),
				router.settingsFor(AiTaskType.REPORT_GENERATION));
	}

	@Test
	void overridesOnlySpecifiedFields() {
		OpenRouterProperties.TaskSettings override = new OpenRouterProperties.TaskSettings();
		override.setModel("strong-model");
		properties.getTasks().put(AiTaskType.ATTACK_PATH_ANALYSIS, override);

		assertEquals(new AiModelRouter.ModelSettings("strong-model", 0.3, 8192),
				router.settingsFor(AiTaskType.ATTACK_PATH_ANALYSIS));
		assertEquals("default-model", router.settingsFor(AiTaskType.FINDING_ANALYSIS).model());
	}

	@Test
	void keepsZeroTemperatureOverride() {
		OpenRouterProperties.TaskSettings override = new OpenRouterProperties.TaskSettings();
		override.setTemperature(0.0);
		override.setMaxTokens(1024);
		properties.getTasks().put(AiTaskType.FINDING_CLASSIFICATION, override);

		assertEquals(new AiModelRouter.ModelSettings("default-model", 0.0, 1024),
				router.settingsFor(AiTaskType.FINDING_CLASSIFICATION));
	}

}
