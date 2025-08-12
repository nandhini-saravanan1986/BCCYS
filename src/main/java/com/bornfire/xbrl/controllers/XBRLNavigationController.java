package com.bornfire.xbrl.controllers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.InputStreamResource;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import com.bornfire.xbrl.config.PasswordEncryption;
import com.bornfire.xbrl.config.SequenceGenerator;
import com.bornfire.xbrl.entities.AccessAndRoles;
import com.bornfire.xbrl.entities.AccessandRolesRepository;
import com.bornfire.xbrl.entities.AlertEntity;
import com.bornfire.xbrl.entities.AlertManagementEntity;
import com.bornfire.xbrl.entities.AlertManagementRepository;
import com.bornfire.xbrl.entities.AlertRep;
import com.bornfire.xbrl.entities.Facility_Repo;
import com.bornfire.xbrl.entities.Facitlity_Entity;
import com.bornfire.xbrl.entities.RBRShareHolder_Entity;
import com.bornfire.xbrl.entities.RBRShareHolder_Repo;
import com.bornfire.xbrl.entities.RBR_CUSTOMER_DATA_V1_REP;
import com.bornfire.xbrl.entities.RBR_Inverstments_Entity;
import com.bornfire.xbrl.entities.RBR_Inverstments_Repo;
import com.bornfire.xbrl.entities.RBR_Legal_Cases_Entity;
import com.bornfire.xbrl.entities.RBR_Legal_Cases_Repo;
import com.bornfire.xbrl.entities.RBRcustomerRepo;
import com.bornfire.xbrl.entities.RBRcustomer_entity;
import com.bornfire.xbrl.entities.Security_Entity;
import com.bornfire.xbrl.entities.Security_Repo;
import com.bornfire.xbrl.entities.UserProfile;
import com.bornfire.xbrl.entities.UserProfileRep;
import com.bornfire.xbrl.entities.XBRLReportsMasterRep;
import com.bornfire.xbrl.entities.BCCYS.BRFValidationsRepo;
import com.bornfire.xbrl.entities.BCCYS.MANUAL_Audit_Rep;
import com.bornfire.xbrl.entities.BCCYS.MANUAL_Service_Entity;
import com.bornfire.xbrl.entities.BCCYS.MANUAL_Service_Rep;
import com.bornfire.xbrl.entities.BCCYS.Provision_Entity;
import com.bornfire.xbrl.entities.BCCYS.Provision_Repo;
import com.bornfire.xbrl.entities.BCCYS.RBROverall_Data_Entity;
import com.bornfire.xbrl.entities.BCCYS.RBRoverall_Data_Repo;
import com.bornfire.xbrl.services.AccessAndRolesServices;
import com.bornfire.xbrl.services.AlertManagementServices;
import com.bornfire.xbrl.services.LoginServices;
import com.bornfire.xbrl.services.RBRReportservice;
import com.bornfire.xbrl.services.ReportServices;
import com.bornfire.xbrl.services.ReportServices.ReportTitle;

import net.sf.jasperreports.engine.JRException;

@Controller
@ConfigurationProperties("default")
public class XBRLNavigationController {

	private static final Logger logger = LoggerFactory.getLogger(XBRLNavigationController.class);
	@Autowired
	SessionFactory sessionFactory;
	@Autowired
	LoginServices loginServices;

	@Autowired
	XBRLReportsMasterRep XBRLReportsMasterReps;

	@Autowired
	AlertRep alertRep;

	@Autowired
	ReportServices reportServices;

	@Autowired
	SequenceGenerator sequence;

	@Autowired
	BRFValidationsRepo brfValidationsRepo;

	@Autowired
	RBRcustomerRepo rBRcustomerRepo;

	@Autowired
	RBRShareHolder_Repo rbrShareHolder_Repo;

	@Autowired
	Facility_Repo facility_Repo;

	@Autowired
	Security_Repo security_Repo;

	@Autowired
	Provision_Repo Provision_Repo;

	@Autowired
	RBR_Inverstments_Repo RBR_Inverstments_Repo;

	@Autowired
	RBR_Legal_Cases_Repo RBR_Legal_Cases_Repo;

	@Autowired
	RBRoverall_Data_Repo RBRoverall_Data_Repo;

	@Autowired
	RBRReportservice RBRReportservice;

	@Autowired
	private AlertManagementRepository alertmanagementrepository;

	@Autowired
	AlertManagementServices alertservices;

	@Autowired
	com.bornfire.xbrl.entities.BCCYS.AUD_SERVICE_REPO AUD_SERVICE_REPO;

	@Autowired
	UserProfileRep userProfileRep;

	@Autowired
	RBR_CUSTOMER_DATA_V1_REP RBR_CUSTOMER_DATA_V1_REP;

	@Autowired
	MANUAL_Audit_Rep mANUAL_Audit_Rep;

	@Autowired
	MANUAL_Service_Rep mANUAL_Service_Rep;


	@Autowired
	AccessAndRolesServices AccessRoleService;

	@Autowired
	AccessandRolesRepository accessandrolesrepository;

	private String auditRefNo;

	private String pagesize;

	public String getPagesize() {
		return pagesize;
	}

	public void setPagesize(String pagesize) {
		this.pagesize = pagesize;
	}

	@RequestMapping("/custom-error")
	public String handleError(HttpServletRequest request, Model model) {
		Object statusCode = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		Object errorMessage = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
		Exception exception = (Exception) request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);

		// Ignore Thymeleaf exceptions by returning a simple message or redirecting
		// elsewhere
		if (exception != null) {
			if (exception instanceof org.thymeleaf.exceptions.TemplateInputException
					|| exception instanceof org.thymeleaf.exceptions.TemplateProcessingException) {
				// For example: return a simple page or ignore it silently
				model.addAttribute("status", statusCode);
				model.addAttribute("message", "A template processing error occurred.");
				return "simple-error"; // Or any other simple error page without details
			}
		}

		model.addAttribute("status", statusCode);
		model.addAttribute("message", errorMessage);

		return "error"; // Your normal error.html template
	}

	@GetMapping("/systemotp")
	public String showOtpForm() {
		return "XBRLOtpvalidation.html"; // Thymeleaf or HTML page
	}

	@PostMapping("/verify-otp")
	public String verifyOtp(@RequestParam("otp") String userOtp, HttpSession session) {
		String actualOtp = (String) session.getAttribute("otp");
		if (actualOtp != null && actualOtp.equals(userOtp)) {
			session.removeAttribute("otp"); // Clear OTP after success
			return "redirect:/Dashboard";
		}
		return "redirect:login?invalidotp";
	}

	@RequestMapping(value = "/", method = { RequestMethod.GET, RequestMethod.POST })
	public String getdashboard(Model md, HttpServletRequest req) {

		String domainid = (String) req.getSession().getAttribute("DOMAINID");
		String userid = (String) req.getSession().getAttribute("USERID");
		String Dashboardpage = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");

		md.addAttribute("menu", "Dashboard");
		md.addAttribute("checkpassExpiry", loginServices.checkpassexpirty(userid));
		md.addAttribute("checkAcctExpiry", loginServices.checkAcctexpirty(userid));
		md.addAttribute("changepassword", loginServices.checkPasswordChangeReq(userid));

		{

			int completed = 0;
			int uncompleted = 0;

			List<ReportTitle> ls = reportServices.getDashBoardRepList(domainid);

			for (ReportTitle var : ls) {
				if (var.getCompletedFlg().equals('Y')) {
					completed++;
				} else {
					uncompleted++;
				}
			}

			md.addAttribute("reportList", ls);
			md.addAttribute("completed", completed);
			md.addAttribute("uncompleted", uncompleted);
		}

		md.addAttribute("menu", "Dashboard");
		return "XBRLDashboard";
	}

	@RequestMapping(value = "Dashboard", method = { RequestMethod.GET, RequestMethod.POST })
	public String dashboard(@RequestParam(name = "frequency", required = false) String frequency, Model md,
			HttpServletRequest req) {

		String domainid = (String) req.getSession().getAttribute("DOMAINID");
		String userid = (String) req.getSession().getAttribute("USERID");
		String Dashboardpage = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");

		System.out.println("Dashboard page is:" + Dashboardpage);
		System.out.println("Branchcode is : " + BRANCHCODE);
		md.addAttribute("menu", "Dashboard");
		md.addAttribute("checkpassExpiry", loginServices.checkpassexpirty(userid));
		md.addAttribute("checkAcctExpiry", loginServices.checkAcctexpirty(userid));
		md.addAttribute("changepassword", loginServices.checkPasswordChangeReq(userid));

		if (Dashboardpage.equalsIgnoreCase("Superadmin")) {

			int completed = 0;
			int uncompleted = 0;

			List<ReportTitle> ls = reportServices.getDashBoardRepList(domainid);

			for (ReportTitle var : ls) {
				if (var.getCompletedFlg().equals('Y')) {
					completed++;
				} else {
					uncompleted++;
				}
			}

			List<Object[]> rawList = XBRLReportsMasterReps.getsinstatus();
			List<Map<String, Object>> brfStatusList = new ArrayList<>();
			for (Object[] row : rawList) {
				Map<String, Object> map = new HashMap<>();
				map.put("reportName", row[0]);
				map.put("description", row[1]);
				map.put("frequency", row[2]);
				map.put("reportingDate", row[3]);
				map.put("status", row[4]);
				brfStatusList.add(map);
			}
			md.addAttribute("brfStatusList", brfStatusList);
			md.addAttribute("menu", "Dashboard");
			// md.addAttribute("netprofit", BRF004ReportServices.getBRF004View_one());

			md.addAttribute("reportList", ls);
			md.addAttribute("completed", completed);
			md.addAttribute("uncompleted", uncompleted);
			md.addAttribute("menu", "Dashboard");
			md.addAttribute("Dashboardpage", Dashboardpage);
			md.addAttribute("selectedFrequency", frequency);

		}

		md.addAttribute("menu", "Dashboard");
		return "XBRLDashboard";
	}

	@RequestMapping(value = "AccessandRoles", method = { RequestMethod.GET, RequestMethod.POST })
	public String IPSAccessandRoles(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String userid, @RequestParam(required = false) Optional<Integer> page,
			@RequestParam(value = "size", required = false) Optional<Integer> size, Model md, HttpServletRequest req) {

		String roleId = (String) req.getSession().getAttribute("ROLEID");
		md.addAttribute("IPSRoleMenu", AccessRoleService.getRoleMenu(roleId));

		if (formmode == null || formmode.equals("list")) {
			md.addAttribute("menu", "ACCESS AND ROLES");
			md.addAttribute("menuname", "ACCESS AND ROLES");
			md.addAttribute("formmode", "list");
			md.addAttribute("AccessandRoles", accessandrolesrepository.rulelist());
		} else if (formmode.equals("add")) {
			md.addAttribute("menuname", "ACCESS AND ROLES - ADD");
			md.addAttribute("formmode", "add");
		} else if (formmode.equals("edit")) {
			md.addAttribute("menuname", "ACCESS AND ROLES - EDIT");
			md.addAttribute("formmode", formmode);
			md.addAttribute("IPSAccessRole", AccessRoleService.getRoleId(userid));
		} else if (formmode.equals("view")) {
			md.addAttribute("menuname", "ACCESS AND ROLES - INQUIRY");
			md.addAttribute("formmode", formmode);
			md.addAttribute("IPSAccessRole", AccessRoleService.getRoleId(userid));

		} else if (formmode.equals("verify")) {
			md.addAttribute("menuname", "ACCESS AND ROLES - VERIFY");
			md.addAttribute("formmode", formmode);
			md.addAttribute("IPSAccessRole", AccessRoleService.getRoleId(userid));

		} else if (formmode.equals("delete")) {
			md.addAttribute("menuname", "ACCESS AND ROLES - DELETE");
			md.addAttribute("formmode", formmode);
			md.addAttribute("IPSAccessRole", AccessRoleService.getRoleId(userid));
		}

		md.addAttribute("adminflag", "adminflag");
		md.addAttribute("userprofileflag", "userprofileflag");

		return "AccessandRoles";
	}

	@RequestMapping(value = "createAccessRole", method = RequestMethod.POST)
	@ResponseBody
	public String createAccessRoleEn(@RequestParam("formmode") String formmode,
			@RequestParam(value = "adminValue", required = false) String adminValue,
			@RequestParam(value = "BRF_ReportsValue", required = false) String BRF_ReportsValue,
			@RequestParam(value = "Basel_ReportsValue", required = false) String Basel_ReportsValue,
			@RequestParam(value = "ArchivalValue", required = false) String ArchivalValue,
			@RequestParam(value = "Audit_InquiriesValue", required = false) String Audit_InquiriesValue,
			@RequestParam(value = "RBR_ReportsValue", required = false) String RBR_ReportsValue,
			@RequestParam(value = "VAT_LedgerValue", required = false) String VAT_LedgerValue,
			@RequestParam(value = "Invoice_DataValue", required = false) String Invoice_DataValue,
			@RequestParam(value = "ReconciliationValue", required = false) String ReconciliationValue,
			@RequestParam(value = "finalString", required = false) String finalString,

			@ModelAttribute AccessAndRoles alertparam, Model md, HttpServletRequest rq) {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		md.addAttribute("IPSRoleMenu", AccessRoleService.getRoleMenu(roleId));

		String msg = AccessRoleService.addPARAMETER(alertparam, formmode, adminValue, BRF_ReportsValue,
				Basel_ReportsValue, ArchivalValue, Audit_InquiriesValue, RBR_ReportsValue, ReconciliationValue,
				VAT_LedgerValue, Invoice_DataValue, finalString, userid);

		return msg;

	}

	@RequestMapping(value = "resetPassword1", method = { RequestMethod.GET, RequestMethod.POST })
	public String showResetPasswordPage(Model md, HttpServletRequest req) {
		String Passworduser = (String) req.getSession().getAttribute("USERID");
		String Passwordresest = (String) req.getSession().getAttribute("PASSWORDERROR");

		md.addAttribute("Resetuserid", Passworduser);
		md.addAttribute("Resetreason", Passwordresest);
		return "XBRLresetPassword"; // Name of the HTML file (resetPassword.html)
	}

	@PostMapping("/resetPassword")
	public String resetPassword(@RequestParam String userid, @RequestParam String newPassword)
			throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
		Optional<UserProfile> userOptional = userProfileRep.findById(userid);
		String encryptedPassword = PasswordEncryption.getEncryptedPassword(newPassword);
		if (userOptional.isPresent()) {
			UserProfile user = userOptional.get();
			user.setPassword(encryptedPassword); // Encrypt the new password
			String localdateval = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
			LocalDate date = LocalDate.parse(localdateval);
			BigDecimal passexpdays = new BigDecimal(user.getPass_exp_days());
			LocalDate date2 = date.plusDays(passexpdays.intValue());
			user.setLog_in_count("1");
			user.setNo_of_attmp(0);
			user.setUser_status("Active");
			user.setUser_status("Active");
			user.setDisable_flg("N");
			user.setUser_locked_flg("N");
			user.setPass_exp_date(new SimpleDateFormat("yyyy-MM-dd").parse(date2.toString()));// Reset the flag
			userProfileRep.save(user);
			return "redirect:login?resetSuccess";
		}

		return "redirect:resetPassword1?error=User not found";
	}

	@GetMapping("/getRoleDetails")
	@ResponseBody
	public AccessAndRoles getRoleDetails(@RequestParam String roleId) {
		System.out.println("role id for fetching is : " + roleId);
		return accessandrolesrepository.findById(roleId).orElse(null);
	}

	@RequestMapping(value = "UserProfile", method = { RequestMethod.GET, RequestMethod.POST })
	public String userprofile(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String userid,
			@RequestParam(value = "page", required = false) Optional<Integer> page,
			@RequestParam(value = "size", required = false) Optional<Integer> size, Model md, HttpServletRequest req) {

		int currentPage = page.orElse(0);
		int pageSize = size.orElse(Integer.parseInt(pagesize));

		String loginuserid = (String) req.getSession().getAttribute("USERID");
		String WORKCLASSAC = (String) req.getSession().getAttribute("WORKCLASS");
		String ROLEIDAC = (String) req.getSession().getAttribute("ROLEID");
		md.addAttribute("RuleIDType", accessandrolesrepository.roleidtype());

		System.out.println("work class is : " + WORKCLASSAC);
		// Logging Navigation
		loginServices.SessionLogging("USERPROFILE", "M2", req.getSession().getId(), loginuserid, req.getRemoteAddr(),
				"ACTIVE");
		Session hs1 = sessionFactory.getCurrentSession();
		md.addAttribute("menu", "USER PROFILE"); // To highlight the menu

		if (formmode == null || formmode.equals("list")) {

			md.addAttribute("formmode", "list");// to set which form - valid values are "edit" , "add" & "list"
			md.addAttribute("WORKCLASSAC", WORKCLASSAC);
			md.addAttribute("ROLEIDAC", ROLEIDAC);
			md.addAttribute("loginuserid", loginuserid);

			Iterable<UserProfile> user = loginServices.getUsersList(ROLEIDAC);

			md.addAttribute("userProfiles", user);

		} else if (formmode.equals("edit")) {

			md.addAttribute("formmode", formmode);
			md.addAttribute("domains", reportServices.getDomainList());
			md.addAttribute("userProfile", loginServices.getUser(userid));

		} else if (formmode.equals("verify")) {

			md.addAttribute("formmode", formmode);
			md.addAttribute("domains", reportServices.getDomainList());
			md.addAttribute("userProfile", loginServices.getUser(userid));

		} else {

			md.addAttribute("formmode", formmode);
			md.addAttribute("domains", reportServices.getDomainList());
			md.addAttribute("FinUserProfiles", loginServices.getFinUsersList());
			md.addAttribute("userProfile", loginServices.getUser(""));

		}

		return "XBRLUserprofile";
	}

	@RequestMapping(value = "Audit", method = RequestMethod.GET)
	public String audit(Model md, HttpServletRequest req) {

		String userid = (String) req.getSession().getAttribute("USERID");
		// Logging Navigation
		loginServices.SessionLogging("AUDIT", "M11", req.getSession().getId(), userid, req.getRemoteAddr(), "ACTIVE");

		LocalDateTime localDateTime = new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

		md.addAttribute("menu", "Audit");
		md.addAttribute("auditlogs", reportServices.getAuditLog(
				Date.from(localDateTime.plusDays(-5).atZone(ZoneId.systemDefault()).toInstant()), new Date()));
		return "XBRLAudit";
	}

	@RequestMapping(value = "Userlog", method = RequestMethod.GET)
	public String userlog(Model md, HttpServletRequest req) {

		String userid = (String) req.getSession().getAttribute("USERID");
		// Logging Navigation
		loginServices.SessionLogging("USERLOG", "M4", req.getSession().getId(), userid, req.getRemoteAddr(), "ACTIVE");

		LocalDateTime localDateTime = new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

		md.addAttribute("menu", "Userlog");
		md.addAttribute("userlog", loginServices.getUserLog(
				Date.from(localDateTime.plusDays(-5).atZone(ZoneId.systemDefault()).toInstant()), new Date()));

		return "XBRLUserLogs";
	}

	@RequestMapping(value = "XBRLReports", method = RequestMethod.GET)
	public String xbrlrep(Model md, HttpServletRequest req) {

		md.addAttribute("menu", "XBRLReports");

		String domainid = (String) req.getSession().getAttribute("DOMAINID");

		md.addAttribute("reportlist", reportServices.getReportsList(domainid));
		return "XBRLReports";
	}

	@RequestMapping(value = "Finuserdata", method = RequestMethod.GET)
	public ModelAndView Finuserdata(@RequestParam String userid) {
		ModelAndView mv = new ModelAndView("XBRLUserprofile::finuserapply");
		mv.addObject("formmode", "add");

		mv.addObject("userProfile", loginServices.getFinUser(userid));
		return mv;

	}

	@RequestMapping(value = "createUser", method = RequestMethod.POST)
	@ResponseBody
	public String createUser(@RequestParam("formmode") String formmode, @ModelAttribute UserProfile userprofile,
			Model md, HttpServletRequest rq) {
		String MOB = (String) rq.getSession().getAttribute("MOBILENUMBER");
		String ROLE = (String) rq.getSession().getAttribute("ROLEDESC");
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		String msg = loginServices.addUser(userprofile, formmode, userid, username, MOB, ROLE);

		return msg;

	}

	@RequestMapping(value = "deleteuser", method = RequestMethod.POST)
	@ResponseBody
	public String deleteuser(@RequestParam("formmode") String userid, Model md, HttpServletRequest rq) {

		String msg = loginServices.deleteuser(userid);

		return msg;

	}

	@RequestMapping(value = "createAlter", method = RequestMethod.POST)
	@ResponseBody
	public String createAlter(@RequestParam("formmode") String formmode, @RequestParam("report_srl") String report_srl,
			@ModelAttribute AlertEntity alertEntity, Model md, HttpServletRequest rq) {
		String MOB = (String) rq.getSession().getAttribute("MOBILENUMBER");
		String ROLE = (String) rq.getSession().getAttribute("ROLEDESC");
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		System.out.println(formmode);
		System.out.println(report_srl);
		String[] a = report_srl.split(",");
		System.out.println(a[0]);
		String report_srl1 = a[0];
		String msg = loginServices.addalerter(alertEntity, formmode, userid, username, MOB, ROLE, report_srl1);

		return msg;

	}

	@RequestMapping(value = "verifyUser", method = RequestMethod.POST)
	@ResponseBody
	public String verifyUser(@ModelAttribute UserProfile userprofile, Model md, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		String msg = loginServices.verifyUser(userprofile, userid);

		return msg;

	}

	@RequestMapping(value = "passwordReset", method = RequestMethod.POST)
	@ResponseBody
	public String passwordReset(@ModelAttribute UserProfile userprofile, Model md, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		String msg = loginServices.passwordReset(userprofile, userid);

		return msg;

	}

	@RequestMapping(value = "defaultpasswordReset", method = RequestMethod.POST)
	@ResponseBody
	public String DefaultpasswordReset(@ModelAttribute UserProfile userprofile, Model md, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		String msg = loginServices.DefaultpasswordReset(userprofile, userid);

		return msg;

	}

	@RequestMapping(value = "changePassword", method = RequestMethod.POST)
	@ResponseBody
	public String changePassword(@RequestParam("oldpass") String oldpass, @RequestParam("newpass") String newpass,
			Model md, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		String msg = loginServices.changePassword(oldpass, newpass, userid);

		return msg;

	}

	@RequestMapping(value = "updateValidity", method = RequestMethod.POST)
	@ResponseBody
	public String updateValidity(@RequestParam("reportid") String reportid, String valid, HttpServletRequest rq) {

		String userid = (String) rq.getSession().getAttribute("USERID");

		return reportServices.updateValidity(reportid, valid, userid);

	}

	@RequestMapping(value = "userLogs/Download", method = RequestMethod.GET)
	@ResponseBody
	public InputStreamResource UserDownload(HttpServletResponse response, @RequestParam String fromdate,
			@RequestParam String todate) throws IOException, SQLException {
		response.setContentType("application/octet-stream");

		InputStreamResource resource = null;

		try {
			Date fromdate2 = new SimpleDateFormat("dd-MM-yyyy").parse(fromdate);
			Date todate2 = new SimpleDateFormat("dd-MM-yyyy").parse(todate);
			File repfile = loginServices.getUserLogFile(fromdate2, todate2);
			response.setHeader("Content-Disposition", "attachment; filename=" + repfile.getName());
			resource = new InputStreamResource(new FileInputStream(repfile));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return resource;
	}

	@RequestMapping(value = "auditLogs/Download", method = RequestMethod.GET)
	@ResponseBody
	public InputStreamResource auditDownload(HttpServletResponse response, @RequestParam String fromdate,
			@RequestParam String todate) throws IOException, SQLException {
		response.setContentType("application/octet-stream");

		InputStreamResource resource = null;

		try {
			Date fromdate2 = new SimpleDateFormat("dd-MM-yyyy").parse(fromdate);
			Date todate2 = new SimpleDateFormat("dd-MM-yyyy").parse(todate);
			File repfile = reportServices.getAuditLogFile(fromdate2, todate2);
			response.setHeader("Content-Disposition", "attachment; filename=" + repfile.getName());
			resource = new InputStreamResource(new FileInputStream(repfile));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return resource;
	}

	@RequestMapping(value = "logoutUpdate", method = RequestMethod.POST)
	@ResponseBody
	public String logoutUpdate(HttpServletRequest req) {

		String msg;

		String userid = (String) req.getSession().getAttribute("USERID");

		try {
			logger.info("Updating Logout");
			loginServices.SessionLogging("LOGOUT", "M0", req.getSession().getId(), userid, req.getRemoteAddr(),
					"IN-ACTIVE");
			msg = "success";
		} catch (Exception e) {
			e.printStackTrace();
			msg = "failed";
		}
		return msg;
	}

	@RequestMapping(value = "createAlert", method = RequestMethod.POST)
	@ResponseBody
	public String createRule(@RequestParam("formmode") String formmode,
			@ModelAttribute AlertManagementEntity alertparam, Model md, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");

		String msg = alertservices.addAlert(alertparam, formmode, userid);

		return msg;

	}

	@RequestMapping(value = "User_Audit", method = RequestMethod.GET)
	public String Service_Audit(Model md, HttpServletRequest req) {
		String userid = (String) req.getSession().getAttribute("USERID");
		System.out.println("The login userid is : " + userid);

		LocalDateTime localDateTime = new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		System.out.println("The time is " + localDateTime);

		md.addAttribute("menu", "Audit");

		// Add both lists to the model
		md.addAttribute("auditlogss", reportServices.getAuditservices());
		md.addAttribute("userAuditLevels", reportServices.getUserAuditLevelList());

		return "User_Audit";
	}

	@RequestMapping(value = "Audits", method = { RequestMethod.GET, RequestMethod.POST })
	public String Audits(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String delete_cust_id,
			@RequestParam(value = "page", required = false) Optional<Integer> page,
			@RequestParam(value = "size", required = false) Optional<Integer> size, Model md, HttpServletRequest req) {
		List<MANUAL_Service_Entity> changes = mANUAL_Service_Rep.getServiceAuditList(auditRefNo); // or use
																									// findByAuditRefNo()

		if (changes == null || changes.isEmpty()) {
			return "";
		}

		StringBuilder sb = new StringBuilder();
		for (MANUAL_Service_Entity entity : changes) {
			sb.append(entity.getField_name()).append(": OldValue: ").append(entity.getOld_value())
					.append(", NewValue: ").append(entity.getNew_value()).append("|||");
		}
		String loginuserid = (String) req.getSession().getAttribute("USERID");
		List<UserProfile> list = loginServices.getUsersListone(loginuserid);
		md.addAttribute("domainid", list);
		if (formmode == null || formmode.equals("list")) {
			System.out.println("hi");
			md.addAttribute("formmode", "list");
			List<MANUAL_Service_Entity> serviceAudits = mANUAL_Service_Rep.getServiceAuditList(auditRefNo);
			md.addAttribute("audits", serviceAudits);
		}
		// md.addAttribute("inlist", AUD_SERVICE_REPO.findbyId(delete_cust_id));

		// to set which form - valid values are "edit" , "add" & "list"
		// md.addAttribute("CustomerKYC",
		// CMGrepository.findAll(PageRequest.of(currentPage, pageSize)));

		else if (formmode.equals("edit")) {
			System.out.println("hlo");
			md.addAttribute("formmode", "edit");
			/* md.addAttribute("inlist", AUD_SERVICE_REPO.getInquirelist()); */
			md.addAttribute("audit", reportServices.getUserAuditLevelList());

		} else if (formmode.equals("add")) {
			md.addAttribute("formmode", "add");
			/* md.addAttribute("inlist", AUD_SERVICE_REPO.getInquirelist()); */
			md.addAttribute("inlist", AUD_SERVICE_REPO.getInquirelist());

		} else if (formmode.equals("delete")) {
			md.addAttribute("formmode", "delete");
			md.addAttribute("inlist", AUD_SERVICE_REPO.getInquirelist());

		} else if (formmode.equals("download")) {
			md.addAttribute("formmode", "download");
			md.addAttribute("inlist", AUD_SERVICE_REPO.getInquirelist());

		}

		else {

			md.addAttribute("formmode", formmode);
		}

		return "Audits";
	}

	@RequestMapping(value = "getchanges2", method = RequestMethod.GET)
	@ResponseBody
	public String getchanges2(@RequestParam("audit_ref_no") String auditRefNo) {
		System.out.println("Received audit_ref_no: " + auditRefNo);

		try {
			List<MANUAL_Service_Entity> changes = mANUAL_Service_Rep.getServiceAudiT(auditRefNo);

			if (changes == null || changes.isEmpty()) {
				return ""; // No data found
			}

			StringBuilder sb = new StringBuilder();
			for (MANUAL_Service_Entity entity : changes) {
				sb.append(entity.getField_name()).append(": OldValue: ").append(entity.getOld_value())
						.append(", NewValue: ").append(entity.getNew_value()).append("|||");
			}

			return sb.toString();

		} catch (Exception e) {
			e.printStackTrace();
			return "Error: " + e.getMessage();
		}
	}

	@RequestMapping(value = "customervarson", method = RequestMethod.POST)
	@ResponseBody
	public String barathvarson(Model md, HttpServletRequest rq, @ModelAttribute RBRcustomer_entity rBRcustomer_entity,
			String cif_no) {
		System.out.println(rBRcustomer_entity.getCif_no());
		System.out.println("The solid Id >>>>>>>>>>>>>>>>>>>>>>>>> " + rBRcustomer_entity.getCename());
		System.out.println("The solid Id >>>>>>>>>>>>>>>>>>>>>>>>> " + rBRcustomer_entity.getGender());
		RBRcustomer_entity up = rBRcustomer_entity;

		rBRcustomerRepo.save(up);
		return "success";
	}

	@RequestMapping(value = "RBRReportDownload", method = RequestMethod.GET)

	@ResponseBody
	public InputStreamResource RBRReportDownload(HttpServletResponse response,
			@RequestParam(value = "filetype", required = false) String filetype,
			@RequestParam(value = "tabName", required = false) String tabName, HttpServletRequest req,
			@RequestParam(value = "operationData", required = false) String operationData)
			throws IOException, SQLException, JRException {

		response.setContentType("application/octet-stream");
		System.out.println(operationData);

		InputStreamResource resource = null;
		try {
			File repfile = reportServices.getRBRFile(filetype, tabName, operationData, req);

			response.setHeader("Content-Disposition", "attachment; filename=" + repfile.getName());
			response.setContentType(
					"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=windows-1256");
			response.setCharacterEncoding("windows-1256");

			try (InputStream inputStream = new FileInputStream(repfile);
					OutputStream outputStream = response.getOutputStream()) {

				byte[] buffer = new byte[1024];
				int bytesRead;

				while ((bytesRead = inputStream.read(buffer)) != -1) {
					outputStream.write(buffer, 0, bytesRead);
				}

				outputStream.flush();
			}
		} catch (FileNotFoundException e) {
			// Handle file not found exception
			e.printStackTrace(); // Consider logging or handling the exception appropriately
		} catch (IOException e) {
			// Handle IO exception
			e.printStackTrace(); // Consider logging or handling the exception appropriately
		} catch (Exception e) {
			// Handle other exceptions
			e.printStackTrace(); // Consider logging or handling the exception appropriately
		}

		return resource;
	}

	// CREATED BY GOWTHAM
	@RequestMapping(value = "RBRMasterReportDownload", method = RequestMethod.GET)
	@ResponseBody
	public void RBRMasterReportDownload(HttpServletResponse response,
			@RequestParam(value = "filetype", required = false, defaultValue = "xlsx") String filetype,
			@RequestParam(value = "formmode", required = true) String formmode, HttpServletRequest req)
			throws IOException, JRException, SQLException {

		System.out.println("Generating Excel report for formmode: " + formmode);

		// Generate the Excel file
		File reportFile = reportServices.getMasterRBRFile(formmode, req);

		if (reportFile == null || !reportFile.exists()) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
			return;
		}

		// Set response headers for file download
		response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
		response.setHeader("Content-Disposition", "attachment; filename=\"" + reportFile.getName() + "\"");
		response.setCharacterEncoding("UTF-8");

		// Write file data to response output stream
		try (InputStream inputStream = new FileInputStream(reportFile);
				OutputStream outputStream = response.getOutputStream()) {

			byte[] buffer = new byte[1024];
			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				outputStream.write(buffer, 0, bytesRead);
			}

			outputStream.flush(); // Ensure all data is written
		} catch (IOException e) {
			e.printStackTrace();
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error processing file");
		}
	}

	@RequestMapping(value = "RBR_Master", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRcustomer_data(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String cif_no, @RequestParam(required = false) String tab, Model md,
			HttpServletRequest req, String cin, @ModelAttribute RBRShareHolder_Entity details1,
			@ModelAttribute RBRcustomer_entity details2, @ModelAttribute Facitlity_Entity details3,
			@ModelAttribute Security_Entity details4, @ModelAttribute Provision_Entity details5,
			@ModelAttribute RBROverall_Data_Entity details6, @ModelAttribute RBR_Legal_Cases_Entity details7,
			@ModelAttribute RBR_Inverstments_Entity details8) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("list")) {
			md.addAttribute("formmode", "list");
			md.addAttribute("userid", "userid");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listcustomer", RBRReportservice.getcustdata());
			} else {
				md.addAttribute("listcustomer", RBRReportservice.getBranchcustdata(BRANCHCODE));
			}

			md.addAttribute("USER_ID", userid);

		} else if (formmode.equals("getbycin")) {
			md.addAttribute("tab", tab);
			md.addAttribute("formmode", "add");
			md.addAttribute("listcustomer", rBRcustomerRepo.getbycif_no(cif_no));
			md.addAttribute("listShare", rbrShareHolder_Repo.getbyview(cin));
			md.addAttribute("listFacility", facility_Repo.getbyview(cin));
			md.addAttribute("listSecurity", security_Repo.getbyview(cin));
			md.addAttribute("listProvision", Provision_Repo.getbyview(cin));
			md.addAttribute("listoverall", RBRoverall_Data_Repo.getbyview(cin));
			md.addAttribute("listlegalcases", RBR_Legal_Cases_Repo.getbyview(cin));
			md.addAttribute("listInverstmentscases", RBR_Inverstments_Repo.getbyview(cin));

		} else if (formmode.equals("verify")) {
			md.addAttribute("formmode", "verify");
			md.addAttribute("listcustomer", rBRcustomerRepo.getcin(cin));
			md.addAttribute("listShare", rbrShareHolder_Repo.getview(cin));
			md.addAttribute("listFacility", facility_Repo.getview(cin));
			md.addAttribute("listSecurity", security_Repo.getview(cin));
			md.addAttribute("listProvision", Provision_Repo.getview(cin));
			md.addAttribute("listoverall", RBRoverall_Data_Repo.getview(cin));
			md.addAttribute("listlegalcases", RBR_Legal_Cases_Repo.getview(cin));
			md.addAttribute("listInverstmentscases", RBR_Inverstments_Repo.getview(cin));

		} else if (formmode.equals("updatecin")) {
			md.addAttribute("formmode", "updatecin");
			md.addAttribute("listcustomer", rBRcustomerRepo.getbycif_no(cif_no));

		} else {
			System.out.println("EMPTY");
		}

		return "RBRMaster";

	}

	@RequestMapping(value = "Customerdata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRcustomer_data(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute RBRcustomer_entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Customerdata")) {
			md.addAttribute("formmode", "Customerdata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Customer Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listcustomerveri", rBRcustomerRepo.getcustomerdata());
				md.addAttribute("listcustomerunveri", rBRcustomerRepo.getcustomerdataunveri());
			} else {
				md.addAttribute("listcustomerveri", rBRcustomerRepo.getcustomerbranchdata(BRANCHCODE));
				md.addAttribute("listcustomerunveri", rBRcustomerRepo.getcustomerbranchdataunveri(BRANCHCODE));
			}
		} else if (formmode.equals("Customeredit")) {
			md.addAttribute("formmode", "Customeredit");
			md.addAttribute("Custedit", rBRcustomerRepo.getcustomeredit(Srl_no));
			md.addAttribute("RBRMenuname", "Customer Edit");
		} else if (formmode.equals("Customeradd")) {
			md.addAttribute("formmode", "Customeradd");
			Long Cust_Srl_no = rBRcustomerRepo.GetCustsrl_no();
			md.addAttribute("Cust_Srl_no", Cust_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Customer Add");
		} else {

		}

		return "RBRMasterdata";

	}

	@RequestMapping(value = "Custdataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String createcustdata(@RequestParam("formmode") String formmode,
			@ModelAttribute RBRcustomer_entity RBRcustomer_entity, Model md, HttpServletRequest rq)
			throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, IOException {
		System.out.println();
		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Custdataoperation(RBRcustomer_entity, formmode, userid, BRANCHCODE);

		return msg;

	}

	@RequestMapping(value = "Partnerdata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRPartnerdata(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute RBRShareHolder_Entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Partnerdata")) {
			md.addAttribute("formmode", "Partnerdata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Partner Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listpartnerveri", rbrShareHolder_Repo.getverifiedpartner());
				md.addAttribute("listpartnerunveri", rbrShareHolder_Repo.getunverifiedpartner());
			} else {
				md.addAttribute("listpartnerveri", rbrShareHolder_Repo.getverifiedbranchpartner(BRANCHCODE));
				md.addAttribute("listpartnerunveri", rbrShareHolder_Repo.getunverifiedpartner());
			}

		} else if (formmode.equals("Partnerdataedit")) {
			md.addAttribute("formmode", "Partnerdataedit");
			RBRcustomer_entity RBRcustomer_entity = rBRcustomerRepo.getcustomeredit(Srl_no);
			md.addAttribute("RBRMenuname", "Partner Edit");
			/*
			 * String SUBBORR = RBRcustomer_entity.getSub_bor_type();
			 * md.addAttribute("SUBBORR", SUBBORR);
			 */
			md.addAttribute("Partneredit", rbrShareHolder_Repo.getpartnersrlno(Srl_no));
		} else if (formmode.equals("Partneradd")) {

			md.addAttribute("formmode", "Partneradd");
			Long Partner_Srl_no = rbrShareHolder_Repo.getAuditRefUUID();
			md.addAttribute("Partner_Srl_no", Partner_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Partner Add");
		} else {

		}

		return "RBRMasterdata";

	}

	@RequestMapping(value = "Partnerdataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String Partnerdataoperation(@RequestParam("formmode") String formmode,
			@ModelAttribute RBRShareHolder_Entity RBRShareHolder_Entity, Model md, HttpServletRequest rq)
			throws Exception {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Partnerdataoperation(RBRShareHolder_Entity, formmode, userid, BRANCHCODE);

		return msg;

	}

	@RequestMapping(value = "Securitydata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRSecuritydata(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute Security_Entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Securitydata")) {
			md.addAttribute("formmode", "Securitydata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Security Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listsecuveri", security_Repo.getsecurityveri());
				md.addAttribute("listsecuunveri", security_Repo.getsecurityunveri());
			} else {
				md.addAttribute("listsecuveri", security_Repo.getsecuritybranch_codeveri(BRANCHCODE));
				md.addAttribute("listsecuunveri", security_Repo.getsecuritybranch_codeunveri(BRANCHCODE));
			}

		} else if (formmode.equals("Securitydataedit")) {

			md.addAttribute("formmode", "Securitydataedit");
			md.addAttribute("Securityedit", security_Repo.Getsecuritysrlno(Srl_no));
			md.addAttribute("RBRMenuname", "Security Edit");
		} else if (formmode.equals("Securityadd")) {
			md.addAttribute("formmode", "Securityadd");
			Long Security_Srl_no = security_Repo.getAuditRefUUID();
			md.addAttribute("Security_Srl_no", Security_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Security Add");
		} else {

		}

		return "RBRMasterdata";

	}

	@RequestMapping(value = "Securitydataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String Securitydataoperation(@RequestParam("formmode") String formmode,
			@ModelAttribute Security_Entity Security_Entity, Model md, HttpServletRequest rq)
			throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, IOException {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Securitydataopr(Security_Entity, formmode, userid, BRANCHCODE, null);

		return msg;

	}

	@PostMapping("/Securitydataoperation/upload")
	@ResponseBody
	public ResponseEntity<String> Securitydataoperation(@RequestParam("formmode") String formmode,
			@RequestParam("file") MultipartFile file, HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		try {

			if (file.isEmpty()) {
				return ResponseEntity.badRequest().body("File is empty.");
			}

			String msg = RBRReportservice.Securitydataupload(file, userid);
			return ResponseEntity.ok("success");
		} catch (Exception ex) {
			ex.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Upload failed: " + ex.getMessage());
		}
	}

	@PostMapping("/Securitydataoperation/verifyall")
	@ResponseBody
	public ResponseEntity<?> verifySecurity(@RequestParam("formmode") String formmode, @RequestBody List<Long> ids,
			HttpServletRequest rq) {
		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Securitydataopr(null, formmode, userid, BRANCHCODE, ids);

		return ResponseEntity.ok(msg);
	}

	@RequestMapping(value = "Facilitydata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRFacilitydata(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute Facitlity_Entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Facilitydata")) {
			md.addAttribute("formmode", "Facilitydata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Facility Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listFaciveri", facility_Repo.getfacveri());
				md.addAttribute("listFaciunveri", facility_Repo.getfacunveri());
			} else {
				md.addAttribute("listFaciveri", facility_Repo.getfacbranch_codeveri(BRANCHCODE));
				md.addAttribute("listFaciunveri", facility_Repo.getfacbranch_codeunveri(BRANCHCODE));
			}
		} else if (formmode.equals("Facilitydataedit")) {

			md.addAttribute("formmode", "Facilitydataedit");
			md.addAttribute("Facdataedit", facility_Repo.getfacsrlno(Srl_no));
			md.addAttribute("RBRMenuname", "Facility Edit");
		} else if (formmode.equals("Facilityadd")) {
			md.addAttribute("formmode", "Facilityadd");
			Long FAC_Srl_no = facility_Repo.getAuditRefUUID();
			md.addAttribute("FAC_Srl_no", FAC_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Facility Add");
		} else {

		}

		return "RBRSecusheets";

	}

	@RequestMapping(value = "Facilitydataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String Facilitydataoperation(@RequestParam("formmode") String formmode,
			@ModelAttribute Facitlity_Entity Facitlity_Entity, Model md, HttpServletRequest rq)
			throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, IOException {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Facilitydataopr(Facitlity_Entity, formmode, userid, BRANCHCODE);

		return msg;

	}

	@RequestMapping(value = "Provisiondata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRProvisiondata(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute Provision_Entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Provisiondata")) {
			md.addAttribute("formmode", "Provisiondata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Provision Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listprovveri", Provision_Repo.getproveri());
				md.addAttribute("listprovunveri", Provision_Repo.getprovunveri());
			} else {
				md.addAttribute("listprovveri", Provision_Repo.getprobranch_codeveri(BRANCHCODE));
				md.addAttribute("listprovunveri", Provision_Repo.getprovbranch_codeunveri(BRANCHCODE));
			}
		} else if (formmode.equals("Provisiondataedit")) {

			md.addAttribute("formmode", "Provisiondataedit");
			md.addAttribute("Provdataedit", Provision_Repo.getprovsrl(Srl_no));
			md.addAttribute("RBRMenuname", "Provision Edit");
		} else if (formmode.equals("Provisionadd")) {
			md.addAttribute("formmode", "Provisionadd");
			Long Pro_Srl_no = Provision_Repo.getAuditRefUUID();
			md.addAttribute("Pro_Srl_no", Pro_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Provision Add");
		} else {

		}

		return "RBRSecusheets";

	}

	@RequestMapping(value = "Provisiondataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String Provisiondataoperation(@RequestParam("formmode") String formmode,
			@ModelAttribute Provision_Entity Provision_Entity, Model md, HttpServletRequest rq)
			throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, IOException {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Provisiondataopr(Provision_Entity, formmode, userid, BRANCHCODE);

		return msg;

	}

	@RequestMapping(value = "Overalldata", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBROveralldata(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String Srl_no, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req, String cin,
			@ModelAttribute RBROverall_Data_Entity details2) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		String WORK_CLASS = (String) req.getSession().getAttribute("WORKCLASS");
		String USER_PERMISSIONS = (String) req.getSession().getAttribute("PERMISSIONS");
		if (formmode == null || formmode.equals("Overalldata")) {
			md.addAttribute("formmode", "Overalldata");
			md.addAttribute("userid", "userid");
			md.addAttribute("RBRMenuname", "Overall Data");

			if (Roleid.equals("RBR")) {
				md.addAttribute("listprovveri", RBRoverall_Data_Repo.getoverallverifi());
				md.addAttribute("listprovunveri", RBRoverall_Data_Repo.getoverallunverifi());
			} else {
				md.addAttribute("listprovveri", RBRoverall_Data_Repo.getoverallbrachverifi(BRANCHCODE));
				md.addAttribute("listprovunveri", RBRoverall_Data_Repo.getoverallbranchunverifi(BRANCHCODE));
			}
		} else if (formmode.equals("Overalldataedit")) {

			md.addAttribute("formmode", "Overalldataedit");
			md.addAttribute("Overalldataedit", RBRoverall_Data_Repo.getsrl_no(Srl_no));
			md.addAttribute("RBRMenuname", "Overall Edit");
		} else if (formmode.equals("Overalladd")) {
			md.addAttribute("formmode", "Overalladd");
			Long Over_Srl_no = RBRoverall_Data_Repo.getAuditRefUUID();
			md.addAttribute("Over_Srl_no", Over_Srl_no.toString());
			md.addAttribute("RBRMenuname", "Overall Add");
		} else {

		}

		return "RBRSecusheets";

	}

	@RequestMapping(value = "Overalldataoperation", method = RequestMethod.POST)
	@ResponseBody
	public String Overalldataoperation(@RequestParam("formmode") String formmode,
			@ModelAttribute RBROverall_Data_Entity RBROverall_Data_Entity, Model md, HttpServletRequest rq)
			throws NoSuchAlgorithmException, InvalidKeySpecException, ParseException, IOException {

		String userid = (String) rq.getSession().getAttribute("USERID");
		String roleId = (String) rq.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) rq.getSession().getAttribute("BRANCHCODE");

		String msg = RBRReportservice.Overalldataoper(RBROverall_Data_Entity, formmode, userid, BRANCHCODE);

		return msg;

	}

	@RequestMapping(value = "RBR_1", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBR_1(@RequestParam(required = false) String formmode, @RequestParam(required = false) String cif_no,
			@RequestParam(required = false) String tab, Model md, HttpServletRequest req) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		if (formmode == null || formmode.equals("list")) {
			md.addAttribute("formmode", "list");
			md.addAttribute("userid", "userid");
			// md.addAttribute("listcustomer", rBRcustomerRepo.getList());

			if (Roleid.equals("RBR")) {
				md.addAttribute("listcustomer", RBR_CUSTOMER_DATA_V1_REP.findAll());
				md.addAttribute("listcustomerRBR1", RBR_CUSTOMER_DATA_V1_REP.Getverified());

			} else {
				md.addAttribute("listcustomer", RBR_CUSTOMER_DATA_V1_REP.getCUSTList(BRANCHCODE));
				md.addAttribute("listcustomerRBR1", RBR_CUSTOMER_DATA_V1_REP.Getverifiedbranch(BRANCHCODE));
			}

			md.addAttribute("USER_ID", userid);

		}

		return "RBRVersion1";

	}

	public Map<String, Boolean> verifyCinStatus() {
		List<RBRcustomer_entity> customerList = rBRcustomerRepo.findAll();
		List<RBR_Inverstments_Entity> investmentList = RBR_Inverstments_Repo.findAll();
		List<RBRShareHolder_Entity> shareholderList = rbrShareHolder_Repo.findAll();
		List<Facitlity_Entity> facilityList = facility_Repo.findAll();
		List<Security_Entity> securityList = security_Repo.findAll();
		List<Provision_Entity> provisionList = Provision_Repo.findAll();
		List<RBROverall_Data_Entity> overallDataList = RBRoverall_Data_Repo.findAll();
		List<RBR_Legal_Cases_Entity> legalCasesList = RBR_Legal_Cases_Repo.findAll();

		Map<String, Boolean> verificationStatus = new HashMap<>();

		Set<String> allCins = new HashSet<>();
		allCins.addAll(customerList.stream().map(RBRcustomer_entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(investmentList.stream().map(RBR_Inverstments_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(shareholderList.stream().map(RBRShareHolder_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(facilityList.stream().map(Facitlity_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(securityList.stream().map(Security_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(provisionList.stream().map(Provision_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(overallDataList.stream().map(RBROverall_Data_Entity::getCin).collect(Collectors.toSet()));
		allCins.addAll(legalCasesList.stream().map(RBR_Legal_Cases_Entity::getCin).collect(Collectors.toSet()));

		for (String cin : allCins) {
			boolean isVerified = true;
			isVerified &= customerList.stream().anyMatch(c -> c.getCin().equals(cin) && "Y".equals(c.getAuth_flg()));
			isVerified &= investmentList.stream().anyMatch(i -> i.getCin().equals(cin) && "Y".equals(i.getAuth_flg()));
			isVerified &= shareholderList.stream().anyMatch(s -> s.getCin().equals(cin) && "Y".equals(s.getAuth_flg()));
			isVerified &= facilityList.stream().anyMatch(f -> f.getCin().equals(cin) && "Y".equals(f.getAuth_flg()));
			isVerified &= securityList.stream().anyMatch(se -> se.getCin().equals(cin) && "Y".equals(se.getAuth_flg()));
			isVerified &= provisionList.stream().anyMatch(p -> p.getCin().equals(cin) && "Y".equals(p.getAuth_flg()));
			isVerified &= overallDataList.stream().anyMatch(o -> o.getCin().equals(cin) && "Y".equals(o.getAuth_flg()));
			isVerified &= legalCasesList.stream().anyMatch(l -> l.getCin().equals(cin) && "Y".equals(l.getAuth_flg()));

			verificationStatus.put(cin, isVerified);
		}

		return verificationStatus;
	}

	@RequestMapping(value = "RBR_Final", method = { RequestMethod.GET, RequestMethod.POST })
	public String RBRFINAL(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String cif_no, @RequestParam(required = false) String tab, Model md,
			HttpServletRequest req, String cin) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Roleid = (String) req.getSession().getAttribute("ROLEID");
		String BRANCHCODE = (String) req.getSession().getAttribute("BRANCHCODE");
		if (Roleid.equals("RBR")) {
			if (formmode == null || formmode.equals("list")) {
				md.addAttribute("formmode", "list");
				md.addAttribute("listcustomer", rBRcustomerRepo.getFinalRBR());
				md.addAttribute("listShare", rbrShareHolder_Repo.getFinalRBR());
				md.addAttribute("listFacility", facility_Repo.getFinalRBR());
				md.addAttribute("listSecurity", security_Repo.getFinalRBR());
				md.addAttribute("listProvision", Provision_Repo.getFinalRBR());
				md.addAttribute("listoverall", RBRoverall_Data_Repo.getFinalRBR());
				md.addAttribute("listlegalcases", RBR_Legal_Cases_Repo.getFinalRBR());
				md.addAttribute("listInverstmentscases", RBR_Inverstments_Repo.getFinalRBR());

			} else {
				System.out.println("EMPTY");
			}
		} else {
			if (formmode == null || formmode.equals("list")) {
				md.addAttribute("formmode", "list");
				md.addAttribute("listcustomer", rBRcustomerRepo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listShare", rbrShareHolder_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listFacility", facility_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listSecurity", security_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listProvision", Provision_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listoverall", RBRoverall_Data_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listlegalcases", RBR_Legal_Cases_Repo.getFinalbranchRBR(BRANCHCODE));
				md.addAttribute("listInverstmentscases", RBR_Inverstments_Repo.getFinalbranchRBR(BRANCHCODE));
			}
		}
		return "RBRFinal";

	}

	@RequestMapping(value = "RBRCustTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRCustTab(@RequestParam String cif_no, @RequestBody RBRcustomer_entity details,
			HttpServletRequest rq) {
		System.out.println("RBRCustTab " + cif_no);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		RBRcustomer_entity up = rBRcustomerRepo.getview(cif_no);
		String msg = "";
		if (up != null) {
			msg = RBRReportservice.RBREditValidation(details);
			if (msg.equals("Verification Ok")) {
				details.setBranch_code(up.getBranch_code());
				details.setCaname("");
				// details.setOperation("UPD");
				details.setModify_flg("Y");
				details.setModify_user(username);
				details.setModify_time(new Date());
				details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
				details.setModify_user(userid);
				details.setReport_date(up.getReport_date());
				details.setBranch(up.getBranch());
				rBRcustomerRepo.save(details);
				return "Edited Successfully";
			} else {
				return msg;
			}
		} else {
			return "Customer not found";
		}
	}

	@RequestMapping(value = "RBRInvestTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRInvestTab(@RequestParam String cin, @RequestBody RBR_Inverstments_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBRInvestTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		RBR_Inverstments_Entity up = RBR_Inverstments_Repo.getview(cin);
		if (up != null) {
			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);
			details.setReport_date(up.getReport_date());
			RBR_Inverstments_Repo.save(details);
			return "Edited Successfully";
		} else {
			return "Investment not found";
		}
	}

	@RequestMapping(value = "RBRLegalTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRLegalTab(@RequestParam String cin, @RequestBody RBR_Legal_Cases_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBRLegalTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		RBR_Legal_Cases_Entity up = RBR_Legal_Cases_Repo.getview(cin);
		if (up != null) {
			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);
			details.setReport_date(up.getReport_date());
			RBR_Legal_Cases_Repo.save(details);
			return "Edited Successfully";
		} else {
			return "Legal not found";
		}
	}

	@RequestMapping(value = "RBROverallTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBROverallTab(@RequestParam String cin, @RequestBody RBROverall_Data_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBROverallTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		RBROverall_Data_Entity up = RBRoverall_Data_Repo.getupdate(details.getSrl_no());
		if (up != null) {
			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);
			details.setReport_date(up.getReport_date());
			RBRoverall_Data_Repo.save(details);
			return "Edited Successfully";
		} else {
			return "Overalldata not found";
		}
	}

	@RequestMapping(value = "RBRProvisionTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRProvisionTab(@RequestParam String cin, @RequestBody Provision_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBRProvisonTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		Provision_Entity up = Provision_Repo.getupdate(details.getSrl_no());
		if (up != null) {
			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);
			details.setReport_date(up.getReport_date());
			Provision_Repo.save(details);

			return "Edited Successfully";
		} else {
			return "Provision not found";
		}
	}

	@RequestMapping(value = "RBRFacilityTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRFacilityTab(@RequestParam String cin, @RequestBody Facitlity_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBRFacilityTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		Facitlity_Entity up = facility_Repo.getupdate(details.getSrl_no());
		if (up != null) {
			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);

			facility_Repo.save(details);
			details.setReport_date(up.getReport_date());
			return "Edited Successfully";
		} else {
			return "Facility not found";
		}
	}

	@RequestMapping(value = "RBRSecurityTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRSecurityTab(@RequestParam String cin, @RequestBody Security_Entity details,
			HttpServletRequest rq) {
		System.out.println("RBRFacilityTab " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		Security_Entity up = security_Repo.getupdate(details.getSrl_no());

		if (up != null) {

			details.setOperation("UPD");
			details.setModify_flg("Y");
			details.setModify_user(username);
			details.setModify_time(new Date());
			details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
			details.setModify_user(userid);
			details.setReport_date(up.getReport_date());
			security_Repo.save(details);
			return "Edited Successfully";

		} else {
			return "Security not found";
		}
	}

	@RequestMapping(value = "RBRPartnerTab", method = RequestMethod.POST)
	@ResponseBody
	public String RBRPartnerTab(@RequestParam String cin, @RequestBody RBRShareHolder_Entity details,
			HttpServletRequest rq) {
		System.out.println("Partner Cin " + cin);
		String userid = (String) rq.getSession().getAttribute("USERID");
		String username = (String) rq.getSession().getAttribute("USERNAME");
		RBRShareHolder_Entity up = rbrShareHolder_Repo.getupdate(details.getSrl_no());
		System.out.println(details.getP_s_cin() + " " + details.getBankcode());
		String Msg = RBRReportservice.RBRPartnervalidation(details);

		if (!cin.equals("ADD")) {

			if (up != null) {
				if (Msg.equals("Validation_done")) {
					details.setOperation("UPD");
					details.setModify_flg("Y");
					details.setModify_user(username);
					details.setModify_time(new Date());
					details.setAuth_flg(up.getAuth_flg() != null ? up.getAuth_flg() : "N");
					details.setModify_user(userid);
					details.setReport_date(up.getReport_date());
					rbrShareHolder_Repo.save(details);
					return "Edited Successfully";
				} else {
					return Msg;
				}
			} else {
				return "Partner and shareholder not found";
			}
		} else {
			RBRShareHolder_Entity rbrshare = rbrShareHolder_Repo.findByCin(details.getCin());
			if (rbrshare.getCin().isEmpty()) {
				return "No data Present for Mentioned Cin";
			} else {

				Long Srl_no = rbrShareHolder_Repo.getAuditRefUUID();
				details.setSrl_no(Srl_no.toString());

				rbrShareHolder_Repo.save(details);

				return "New Partner data Added";

			}
		}
	}

	@RequestMapping(value = "RBRUpdatecin", method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<String> RBRUpdatecin(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String cin_Cust1, @RequestParam(required = false) String cif_no_Cust1,
			@RequestParam(required = false) String csno_Cust1, Model md, HttpServletRequest req) {
		String userid = (String) req.getSession().getAttribute("USERID");
		String Msg;
		RBRcustomer_entity UP = rBRcustomerRepo.getview(cif_no_Cust1);

		UP.setCin(cin_Cust1);
		UP.setCsno(csno_Cust1);

		rBRcustomerRepo.save(UP);

		List<RBRShareHolder_Entity> up11 = rbrShareHolder_Repo.getbycustid(cif_no_Cust1);

		for (RBRShareHolder_Entity up1 : up11) {
			if (up1 != null) {
				String authFlag = up1.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up1.setCin(cin_Cust1);
					up1.setCsno(csno_Cust1);
					rbrShareHolder_Repo.save(up1);
				}
			}
		}

		List<Facitlity_Entity> up31 = facility_Repo.getbycustid(cif_no_Cust1);
		for (Facitlity_Entity up3 : up31) {
			if (up3 != null) {
				String authFlag = up3.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up3.setCin(cin_Cust1);
					up3.setCsno(csno_Cust1);

					facility_Repo.save(up3);
				}
			}
		}

		List<Security_Entity> up41 = security_Repo.getbycustid(cif_no_Cust1);
		for (Security_Entity up4 : up41) {
			if (up4 != null) {
				String authFlag = up4.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up4.setCin(cin_Cust1);
					up4.setCsno(csno_Cust1);
					security_Repo.save(up4);
				}
			}
		}
		List<Provision_Entity> up51 = Provision_Repo.getbycustid(cif_no_Cust1);
		for (Provision_Entity up5 : up51) {
			if (up5 != null) {
				String authFlag = up5.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up5.setCin(cin_Cust1);
					up5.setCsno(csno_Cust1);

					Provision_Repo.save(up5);
				}
			}
		}
		List<RBROverall_Data_Entity> up61 = RBRoverall_Data_Repo.getbycustid(cif_no_Cust1);
		for (RBROverall_Data_Entity up6 : up61) {
			if (up6 != null) {
				String authFlag = up6.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up6.setCin(cin_Cust1);
					up6.setCsno(csno_Cust1);

					RBRoverall_Data_Repo.save(up6);
				}
			}
		}

		RBRReportservice.Rbrauditservice(userid, "All CCSYS TABLES", "CIN and CSNO",
				cin_Cust1 + " - CIN AND " + csno_Cust1 + " - CSNO UPDATE");

		Msg = "Cin Updated successfully";
		return ResponseEntity.ok(Msg);

	}

	@RequestMapping(value = "RBRVerify", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> RBRVerify(@RequestParam String cin, @RequestParam String Datatype,
			@RequestParam String Srl_no, @ModelAttribute RBRShareHolder_Entity details1,
			@ModelAttribute RBRcustomer_entity details2, @ModelAttribute Facitlity_Entity details3,
			@ModelAttribute Security_Entity details4, @ModelAttribute Provision_Entity details5,
			@ModelAttribute RBROverall_Data_Entity details6, @ModelAttribute RBR_Legal_Cases_Entity details7,
			@ModelAttribute RBR_Inverstments_Entity details8, HttpServletRequest rq, Model md) {

		Map<String, Object> response = new HashMap<>();
		String msg = "";
		String userid = (String) rq.getSession().getAttribute("USERID");
		// Boolean a = verifyAndUpdateAuthFlg(cin);
		// md.addAttribute("allVerified", a);

		if (Datatype.equals("CUSTOMERDATA")) {

			msg = RBRReportservice.RBRValidation(cin);

			RBRcustomer_entity up2 = rBRcustomerRepo.findById(Srl_no).get();
			if (up2 != null && up2.getCin() != null) {
				String authFlag = up2.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up2.setAuth_flg("Y");
					up2.setAuth_user(userid);
					up2.setAuth_time(new Date());
					rBRcustomerRepo.save(up2);

					RBRReportservice.Rbrauditservice(userid, "Customer data", "Customer verification",
							up2.getCif_no() + " is verified and Srl no is " + up2.getSrl_no());

					msg = "Customer data successfully verified!";
				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}

		}

		if (Datatype.equals("SHAREHOLDERDATA")) {

			RBRShareHolder_Entity up1 = rbrShareHolder_Repo.findById(Srl_no).get();

			if (up1 != null && up1.getCin() != null) {
				String authFlag = up1.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up1.setAuth_flg("Y");
					up1.setAuth_user(userid);
					up1.setAuth_time(new Date());
					rbrShareHolder_Repo.save(up1);

					RBRReportservice.Rbrauditservice(userid, "partner data", "Partner verification",
							up1.getP_s_cin() + " is verified and Srl no is " + up1.getSrl_no());

					msg = "Partner data successfully verified!";

				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}

		}
		if (Datatype.equals("FACILITYDATA")) {
			Facitlity_Entity up3 = facility_Repo.findById(Srl_no).get();

			if (up3 != null && up3.getCin() != null) {
				String authFlag = up3.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up3.setAuth_flg("Y");
					up3.setAuth_user(userid);
					up3.setAuth_time(new Date());
					facility_Repo.save(up3);

					RBRReportservice.Rbrauditservice(userid, "Facility data", "Facility verification",
							up3.getFac_id() + " is verified and Srl no is " + up3.getSrl_no());

					msg = "Facility data successfully verified!";

				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}
		}
		if (Datatype.equals("SECURITYDATA")) {
			Security_Entity up4 = security_Repo.findById(Srl_no).get();

			if (up4 != null && up4.getCin() != null) {
				String authFlag = up4.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up4.setAuth_flg("Y");
					up4.setAuth_user(userid);
					up4.setAuth_time(new Date());
					security_Repo.save(up4);

					RBRReportservice.Rbrauditservice(userid, "Security data", "Security verification",
							up4.getFac_id() + " is verified and Srl no is " + up4.getSrl_no());

					msg = "Security data successfully verified!";
				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}
		}
		if (Datatype.equals("PROVISIONDATA")) {
			Provision_Entity up5 = Provision_Repo.findById(Srl_no).get();

			if (up5 != null && up5.getCin() != null) {
				String authFlag = up5.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up5.setAuth_flg("Y");
					up5.setAuth_user(userid);
					up5.setAuth_time(new Date());
					Provision_Repo.save(up5);

					RBRReportservice.Rbrauditservice(userid, "Provision data", "Provision verification",
							up5.getFac_id() + " is verified and Srl no is " + up5.getSrl_no());

					msg = "Provision data successfully verified!";
				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}
		}
		if (Datatype.equals("OVERALLDATA")) {
			RBROverall_Data_Entity up6 = RBRoverall_Data_Repo.findById(Srl_no).get();

			if (up6 != null && up6.getCin() != null) {
				String authFlag = up6.getAuth_flg();
				if (authFlag != null && authFlag.equals("N")) {
					up6.setAuth_flg("Y");
					up6.setAuth_user(userid);
					up6.setAuth_time(new Date());
					RBRoverall_Data_Repo.save(up6);

					RBRReportservice.Rbrauditservice(userid, "Overall data", "Overall verification",
							up6.getCin() + " is verified and Srl no is " + up6.getSrl_no());

					msg = "Overall data successfully verified!";
				}
			} else {
				msg = "Verification failed: CIN is missing. " + "Please provide a valid CIN to proceed.";
			}

		}
		response.put("message", msg);

		response.put("cin", cin);
		return response;
	}

	public boolean verifyAndUpdateAuthFlg(String cin) {
		List<RBRcustomer_entity> customerList = rBRcustomerRepo.findAll();
		List<RBR_Inverstments_Entity> investmentList = RBR_Inverstments_Repo.findAll();
		List<RBRShareHolder_Entity> shareholderList = rbrShareHolder_Repo.findAll();
		List<Facitlity_Entity> facilityList = facility_Repo.findAll();
		List<Security_Entity> securityList = security_Repo.findAll();
		List<Provision_Entity> provisionList = Provision_Repo.findAll();
		List<RBROverall_Data_Entity> overallDataList = RBRoverall_Data_Repo.findAll();
		List<RBR_Legal_Cases_Entity> legalCasesList = RBR_Legal_Cases_Repo.findAll();

		RBRcustomer_entity customer = customerList.stream().filter(entity -> cin.equals(entity.getCin())).findFirst()
				.orElse(null);
		System.out.println("Customer: " + customer);

		RBR_Inverstments_Entity investment = investmentList.stream().filter(entity -> cin.equals(entity.getCin()))
				.findFirst().orElse(null);
		System.out.println("Investment: " + investment);

		RBRShareHolder_Entity shareholder = shareholderList.stream().filter(entity -> cin.equals(entity.getCin()))
				.findFirst().orElse(null);
		System.out.println("Shareholder: " + shareholder);

		Facitlity_Entity facility = facilityList.stream().filter(entity -> cin.equals(entity.getCin())).findFirst()
				.orElse(null);
		System.out.println("Facility: " + facility);

		Security_Entity security = securityList.stream().filter(entity -> cin.equals(entity.getCin())).findFirst()
				.orElse(null);
		System.out.println("Security: " + security);

		Provision_Entity provision = provisionList.stream().filter(entity -> cin.equals(entity.getCin())).findFirst()
				.orElse(null);
		System.out.println("Provision: " + provision);

		RBROverall_Data_Entity overallData = overallDataList.stream().filter(entity -> cin.equals(entity.getCin()))
				.findFirst().orElse(null);
		System.out.println("Overall Data: " + overallData);

		RBR_Legal_Cases_Entity legalCases = legalCasesList.stream().filter(entity -> cin.equals(entity.getCin()))
				.findFirst().orElse(null);
		System.out.println("Legal Cases: " + legalCases);

		boolean allVerified = (customer != null && "Y".equals(customer.getAuth_flg()))
				&& (investment != null && "Y".equals(investment.getAuth_flg()))
				&& (shareholder != null && "Y".equals(shareholder.getAuth_flg()))
				&& (facility != null && "Y".equals(facility.getAuth_flg()))
				&& (security != null && "Y".equals(security.getAuth_flg()))
				&& (provision != null && "Y".equals(provision.getAuth_flg()))
				&& (overallData != null && "Y".equals(overallData.getAuth_flg()))
				&& (legalCases != null && "Y".equals(legalCases.getAuth_flg()));
		System.out.println(allVerified + "allVerifiedallVerifiedallVerifiedallVerified");
		return allVerified;
	}

	@RequestMapping(value = "ManualAudittrailvalue", method = RequestMethod.GET)
	public String ManualAudittrailvalue(@RequestParam(required = false) String formmode,
			@RequestParam(required = false) String srlno, String keyword, Model md, HttpServletRequest req) {
		if (formmode == null || formmode.equals("list")) {
			md.addAttribute("formmode", "list");
		} else if (formmode.equals("upload")) {
			md.addAttribute("formmode", "upload");
		} else if (formmode.equals("list1")) {
			md.addAttribute("formmode", "list1");
		} else if (formmode.equals("upload1")) {
			md.addAttribute("formmode", "upload1");
		} else if (formmode.equals("upload2")) {
			md.addAttribute("formmode", "upload2");
		} else if (formmode.equals("upload3")) {
			md.addAttribute("formmode", "upload3");
		}

		return "Manual_Audit_service";
	}

	@RequestMapping(value = "Manualuseractivities", method = { RequestMethod.GET, RequestMethod.POST })
	public String Manualuseractivities(@RequestParam(required = false) String formmode, Model model, String cust_id,
			@RequestParam(required = false) @DateTimeFormat(pattern = "dd-MM-yyyy") Date Fromdate,
			HttpServletRequest request) {
		LocalDate today = LocalDate.now(); // Get today's date
		Date fromDateToUse; // Declare a variable for the date to use

		if (Fromdate != null) {
			// If Fromdate has a value, use it
			fromDateToUse = Fromdate;
		} else {
			// If Fromdate has no value, use today's date
			fromDateToUse = java.sql.Date.valueOf(today);
		}

		if (formmode == null || formmode.equals("list")) {
			model.addAttribute("formmode", "list");

			// Fetch the audit list based on the determined date

			model.addAttribute("AuditList", mANUAL_Audit_Rep.getauditListLocalvaluesbusiness(fromDateToUse));

		}

		return "Manual_User_Activity";
	}

	@RequestMapping(value = "ManualOperationLogsval", method = { RequestMethod.GET, RequestMethod.POST })
	public String ManualOperationLogsval(@RequestParam(required = false) String formmode, Model model, String cust_id,
			@RequestParam(required = false) @DateTimeFormat(pattern = "dd-MM-yyyy") Date Fromdate,
			HttpServletRequest request) {

		LocalDate today = LocalDate.now(); // Get today's date
		Date fromDateToUse; // Declare a variable for the date to use
		if (Fromdate != null) {
			// If Fromdate has a value, use it
			fromDateToUse = Fromdate;
		} else {
			// If Fromdate has no value, use today's date
			fromDateToUse = java.sql.Date.valueOf(today);
		}

		if (formmode == null || formmode.equals("list")) {
			model.addAttribute("formmode", "list");
			model.addAttribute("AuditList", mANUAL_Service_Rep.getauditListLocalvaluesbusiness(fromDateToUse));
		}

		return "Manual_Business_Activity";
	}

	// Helper method to format date values as 'DD-MM-YYYY'
	private String formatDate(String value, SimpleDateFormat dateFormat) {
		try {
			// Assuming the value is in a valid date format that SimpleDateFormat can parse
			Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(value); // Adjust this pattern based on
																						// your date format
			return dateFormat.format(date); // Return formatted date as 'DD-MM-YYYY'
		} catch (Exception e) {
			// If parsing fails, return the original value
			return value;
		}
	}

	@RequestMapping(value = "Generateloginotp", method = { RequestMethod.GET, RequestMethod.POST })
	@ResponseBody
	public String Generateloginotp(@RequestParam("Userid") String Userid) {
		String msg = "success";
		System.out.println(msg);
		return msg;
	}
}
