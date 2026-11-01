package Security_Scanner.Security_Scanner.controller;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import Security_Scanner.Security_Scanner.dto.scanfinding.ScanFindingResponse;
import Security_Scanner.Security_Scanner.dto.scan.ScanResponse;
import Security_Scanner.Security_Scanner.service.AssetService;
import Security_Scanner.Security_Scanner.service.FindingService;
import Security_Scanner.Security_Scanner.service.ScanOrchestrator;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class FindingController {

	private final FindingService findingService;
	private final ScanOrchestrator scanOrchestrator;
	private final AssetService assetService;

	@GetMapping("/findings")
	public String list(@RequestParam(defaultValue = "0") int page, Model model) {
		page = Math.max(page, 0);

		List<ScanFindingResponse> findings = findingService.findAll(page);

		model.addAttribute("findings", findings);
		model.addAttribute("page", page);
		model.addAttribute("hasNext", findings.size() == FindingService.PAGE_SIZE);
		model.addAttribute("hasPrev", page > 0);

		return "findings/list";
	}

	@GetMapping("/findings/{id}")
	public String detail(@PathVariable Long id, Model model) {
		ScanFindingResponse finding = findingService.findById(id);
		ScanResponse scan = scanOrchestrator.findById(finding.scanId());

		model.addAttribute("finding", finding);
		model.addAttribute("scan", scan);
		model.addAttribute("asset", assetService.findById(scan.assetId()));

		return "findings/detail";
	}

}
