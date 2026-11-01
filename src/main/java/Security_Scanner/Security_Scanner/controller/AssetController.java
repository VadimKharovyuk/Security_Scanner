package Security_Scanner.Security_Scanner.controller;

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import Security_Scanner.Security_Scanner.dto.asset.AssetRequest;
import Security_Scanner.Security_Scanner.dto.asset.AssetResponse;
import Security_Scanner.Security_Scanner.dto.project.ProjectResponse;
import Security_Scanner.Security_Scanner.service.asset.AssetService;
import Security_Scanner.Security_Scanner.service.project.ProjectService;
import Security_Scanner.Security_Scanner.service.scan.ScanOrchestrator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AssetController {

	private final AssetService assetService;
	private final ProjectService projectService;
	private final ScanOrchestrator scanOrchestrator;

	@GetMapping("/assets")
	public String list(@RequestParam(defaultValue = "0") int page, Model model) {
		page = Math.max(page, 0);

		List<AssetResponse> assets = assetService.findAll(page);

		model.addAttribute("assets", assets);
		model.addAttribute("page", page);
		model.addAttribute("hasNext", assets.size() == AssetService.PAGE_SIZE);
		model.addAttribute("hasPrev", page > 0);

		return "assets/list";
	}

	@GetMapping("/assets/{id}")
	public String detail(@PathVariable Long id, Model model) {
		AssetResponse asset = assetService.findById(id);

		model.addAttribute("asset", asset);
		model.addAttribute("project", projectService.findById(asset.projectId()));
		model.addAttribute("scans", scanOrchestrator.findByAsset(id, 0));

		return "assets/detail";
	}

	@GetMapping("/projects/{projectId}/assets/new")
	public String createForm(@PathVariable Long projectId, Model model) {
		ProjectResponse project = projectService.findById(projectId);

		AssetRequest request = new AssetRequest();
		request.setProjectId(projectId);

		model.addAttribute("assetRequest", request);
		model.addAttribute("project", project);

		return "assets/form";
	}

	@PostMapping("/projects/{projectId}/assets")
	public String create(@PathVariable Long projectId,
			@Valid @ModelAttribute("assetRequest") AssetRequest request,
			BindingResult bindingResult, Model model) {

		request.setProjectId(projectId);

		if (bindingResult.hasErrors()) {
			model.addAttribute("project", projectService.findById(projectId));
			return "assets/form";
		}

		assetService.create(request);
		return "redirect:/projects/" + projectId;
	}

	@PostMapping("/assets/{id}/deactivate")
	public String deactivate(@PathVariable Long id) {
		AssetResponse asset = assetService.deactivate(id);
		return "redirect:/projects/" + asset.projectId();
	}

	@PostMapping("/assets/{id}/delete")
	public String delete(@PathVariable Long id) {
		AssetResponse asset = assetService.findById(id);
		assetService.delete(id);
		return "redirect:/projects/" + asset.projectId();
	}

}
