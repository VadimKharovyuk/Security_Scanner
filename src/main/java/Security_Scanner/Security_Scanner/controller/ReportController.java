package Security_Scanner.Security_Scanner.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

import Security_Scanner.Security_Scanner.dto.report.ScanReport;
import Security_Scanner.Security_Scanner.service.report.ReportService;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class ReportController {

	private final ReportService reportService;

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
