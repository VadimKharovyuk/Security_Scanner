package Security_Scanner.Security_Scanner.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.service.ai.ScanAnalysisService;
import Security_Scanner.Security_Scanner.service.report.ReportService;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class ReportController {

	private final ReportService reportService;
	private final ScanAnalysisService scanAnalysisService;

	/**
	 * POST, потому что каждый вызов обращается к платной модели.
	 */
	@PostMapping("/scans/{id}/analysis")
	public String analysis(@PathVariable Long id, Model model) {
		model.addAttribute("scanId", id);
		model.addAttribute("analysis", scanAnalysisService.analyze(id));
		return "reports/analysis";
	}

	@GetMapping("/scans/{id}/report")
	public String html(@PathVariable Long id, Model model) {
		model.addAttribute("report", reportService.build(id));
		return "reports/scan";
	}

	@GetMapping("/api/reports/{id}")
	@ResponseBody
	public ScanReport json(@PathVariable Long id) {
		return reportService.build(id);
	}

}
