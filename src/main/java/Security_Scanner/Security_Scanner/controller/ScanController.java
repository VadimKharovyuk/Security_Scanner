package Security_Scanner.Security_Scanner.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import Security_Scanner.Security_Scanner.dto.scan.ScanRequest;
import Security_Scanner.Security_Scanner.dto.scan.ScanResponse;
import Security_Scanner.Security_Scanner.service.AssetService;
import Security_Scanner.Security_Scanner.service.FindingService;
import Security_Scanner.Security_Scanner.service.ScanOrchestrator;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class ScanController {

	private final ScanOrchestrator scanOrchestrator;
	private final AssetService assetService;
	private final FindingService findingService;

	@GetMapping("/scans")
	public String list(@RequestParam(defaultValue = "0") int page, Model model) {
		page = Math.max(page, 0);

		List<ScanResponse> scans = scanOrchestrator.findAll(page);

		model.addAttribute("scans", scans);
		model.addAttribute("page", page);
		model.addAttribute("hasNext", scans.size() == ScanOrchestrator.PAGE_SIZE);
		model.addAttribute("hasPrev", page > 0);

		return "scans/list";
	}

	@GetMapping("/scans/{id}")
	public String detail(@PathVariable Long id, Model model) {
		ScanResponse scan = scanOrchestrator.findById(id);

		model.addAttribute("scan", scan);
		model.addAttribute("asset", assetService.findById(scan.assetId()));
		model.addAttribute("findings", findingService.findByScan(id));

		return "scans/detail";
	}

	@PostMapping("/assets/{assetId}/scans")
	public String start(@PathVariable Long assetId) {
		ScanRequest request = new ScanRequest();
		request.setAssetId(assetId);

		ScanResponse scan = scanOrchestrator.create(request);

		return "redirect:/scans/" + scan.id();
	}

	@PostMapping("/scans/{id}/cancel")
	public String cancel(@PathVariable Long id) {
		scanOrchestrator.cancel(id);
		return "redirect:/scans/" + id;
	}

	@PostMapping("/scans/{id}/delete")
	public String delete(@PathVariable Long id) {
		scanOrchestrator.delete(id);
		return "redirect:/scans";
	}

}
