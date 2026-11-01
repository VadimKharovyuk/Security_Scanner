package Security_Scanner.Security_Scanner.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import Security_Scanner.Security_Scanner.dto.ProjectRequest;
import Security_Scanner.Security_Scanner.dto.ProjectResponse;
import Security_Scanner.Security_Scanner.service.AssetService;
import Security_Scanner.Security_Scanner.service.ProjectService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/projects")
@RequiredArgsConstructor
public class ProjectController {

	private final ProjectService projectService;
	private final AssetService assetService;

	@GetMapping
	public String list(@RequestParam(defaultValue = "0") int page, Model model) {
		page = Math.max(page, 0);

		List<ProjectResponse> projects = projectService.findAll(page);

		model.addAttribute("projects", projects);
		model.addAttribute("page", page);
		model.addAttribute("hasNext", projects.size() == ProjectService.PAGE_SIZE);
		model.addAttribute("hasPrev", page > 0);

		return "projects/list";
	}

	@GetMapping("/new")
	public String createForm(Model model) {
		model.addAttribute("projectRequest", new ProjectRequest());
		model.addAttribute("actionUrl", "/projects");
		model.addAttribute("formTitle", "Новый проект");
		return "projects/form";
	}

	@PostMapping
	public String create(@Valid @ModelAttribute("projectRequest") ProjectRequest request,
			BindingResult bindingResult, Model model) {

		if (bindingResult.hasErrors()) {
			model.addAttribute("actionUrl", "/projects");
			model.addAttribute("formTitle", "Новый проект");
			return "projects/form";
		}

		projectService.create(request);
		return "redirect:/projects";
	}

	@GetMapping("/{id}")
	public String detail(@PathVariable Long id, Model model) {
		ProjectResponse project = projectService.findById(id);

		model.addAttribute("project", project);
		model.addAttribute("assets", assetService.findByProject(id, 0));

		return "projects/detail";
	}

	@GetMapping("/{id}/edit")
	public String editForm(@PathVariable Long id, Model model) {
		ProjectResponse project = projectService.findById(id);

		ProjectRequest request = new ProjectRequest();
		request.setName(project.name());
		request.setDescription(project.description());

		model.addAttribute("projectRequest", request);
		model.addAttribute("actionUrl", "/projects/" + id);
		model.addAttribute("formTitle", "Редактирование проекта");

		return "projects/form";
	}

	@PostMapping("/{id}")
	public String update(@PathVariable Long id,
			@Valid @ModelAttribute("projectRequest") ProjectRequest request,
			BindingResult bindingResult, Model model) {

		if (bindingResult.hasErrors()) {
			model.addAttribute("actionUrl", "/projects/" + id);
			model.addAttribute("formTitle", "Редактирование проекта");
			return "projects/form";
		}

		projectService.update(id, request);
		return "redirect:/projects/" + id;
	}

	@PostMapping("/{id}/delete")
	public String delete(@PathVariable Long id) {
		projectService.delete(id);
		return "redirect:/projects";
	}

}
