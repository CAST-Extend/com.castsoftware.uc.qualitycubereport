package com.castsoftware.uc.qualitycubereport;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.text.ParseException;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;

import org.json.JSONObject;

import org.apache.log4j.Logger;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

/**
 * Generation of reports that consolidate data from the Rest API (heath or
 * engineering) in Excel
 * 
 * @author MMR
 *
 */
public class QualityCubeReport {

	//////////////////////////////////////////////////////////////////////////////////////////////////

	// Please also change the version in version.properties file
	private static final String VERSION = "1.0.2";

	private static final String FILTER_EXTENSION_VERSION_LAST = "LAST";
	private static final String FILTER_EXTENSION_VERSION_ALL = "ALL";
	
	//////////////////////////////////////////////////////////////////////////////////////////////////
	// command line short and long keys

	// short key params
	private final static String OPTION_SK_LOOKUP_EXTENSIONS = "lkext";
	private final static String OPTION_SK_LOOKUP_QR = "lkqr";
	private final static String OPTION_SK_AIPVERSION = "aipver";	
	private final static String OPTION_SK_FILTEREXTVERSION = "extfilver";	
	
	// Lonk key params
	private final static String OPTION_LK_LOOKUP_EXTENSIONS = "lookupExtensionsDetails";	
	private final static String OPTION_LK_LOOKUP_QR = "lookupQualityRuleDetails";	
	private final static String OPTION_LK_AIPVERSION = "AIPVersion";		
	private final static String OPTION_LK_FILTEREXTVERSION = "filterExtensionsVersion";		
	
	//////////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * Class logger
	 */
	private Logger logger = null;
	
	
	// Lookup the detail of quality rules
	private boolean qualityRuleDetailLookup = false;
	
	// Lookup the detail of extensions
	private boolean extensionsDetailLookup = false;
	
	// AIP Version to search
	private String AIPVersion = null;
	
	// Extension version (last by default)
	private String extensionVersionFilter = FILTER_EXTENSION_VERSION_LAST;
	
	private QualityCubeReport() {
		logger = Logger.getLogger("MainLogger");
	}

	/**
	 * Main method
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		QualityCubeReport reportgen = new QualityCubeReport();
		reportgen.parseCmdLineParameters(args);
		//TODO Check parameters with clear messages
		//reportgen.checkParameters();
		reportgen.run();
	}

	public void run()  throws Exception {
		logInputs();
		extractQualityCube();
	}
	
	/**
	 * Check the JSON errors
	 * 
	 * @param responseBody
	 * @return
	 */
	private JSONArray checkJSONArrayResponseBodyErrors(String responseBody) {
		JSONArray jsonArray = null;
		if (responseBody == null)
			return null;
		try {
			jsonArray = new JSONArray(responseBody);
		} catch (Exception e) {
			if ("A JSONArray text must start with '[' at character 1".equals(e.getMessage())) {
				logger.error("Error " + responseBody.toString());
			}
			logger.error("Error " + e.getMessage());
			jsonArray = new JSONArray();
		}
		return jsonArray;
	}

	
	
	/**
	 * Check the JSON errors
	 * 
	 * @param responseBody
	 * @return
	 */
	private JSONObject checkJSONObjectResponseBodyErrors(String responseBody) {
		JSONObject jsonObject = null;
		if (responseBody == null)
			return null;
		try {
			jsonObject = new JSONObject(responseBody);
		} catch (Exception e) {
			logger.error("Error " + e.getMessage());
			jsonObject = new JSONObject();
		}
		return jsonObject;
	}

	/***
	 * Execute a Rest API request
	 * 
	 * @param URI
	 * @param user
	 * @param pwd
	 * @param encodingToUse
	 * @param logger
	 * @return
	 * @throws Exception
	 */
	private String executeRestAPIRequest(String URI, String user, String pwd, String encodingToUse, Logger logger)
			throws Exception {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		String responseBody = null;
		try {
			HttpGet httpget = new HttpGet(URI);
			// JSON
			httpget.addHeader("accept", "application/json");
			// authentication parameters
			String encoding = DatatypeConverter.printBase64Binary((user + ":" + pwd).getBytes(encodingToUse));
			httpget.setHeader("Authorization", "Basic " + encoding);

			logger.info("Executing request " + httpget.getRequestLine() + " -- [Begin] ");
			response = httpclient.execute(httpget);
			logger.debug("	HTTP code=" + response.getStatusLine());
			responseBody = EntityUtils.toString(response.getEntity());
			logger.debug(responseBody);

			// Parsing the JSON structure
			EntityUtils.consume(response.getEntity());
			logger.info("Executing request " + httpget.getRequestLine() + " -- [End] ");
		} catch (Exception l_exception) {
			logger.error(l_exception.getMessage(), l_exception);
			throw l_exception;
		} finally {
			if (response != null)
				response.close();
			if (response != null)
				response.close();
		}
		return responseBody;
	}

	
	protected void logInputs() throws Exception {
		logger.info("==============================");
		logger.info("Version:" + VERSION);
		logger.info("Parameters:");
		logger.info("Lookup the quality rules details :" + isQualityRuleDetailLookup());
		logger.info("Lookup the extensions details :" + isExtensionsDetailLookup());
		logger.info("Input AIP Version :" + getAIPVersion());
		logger.info("Filter extensions version :" + getExtensionVersionFilter());		
		logger.info("==============================");
	}
	
	
	private Options constructCmdLineOptions() {
		Options options = new Options();
		options.addOption(OPTION_SK_LOOKUP_EXTENSIONS, OPTION_LK_LOOKUP_EXTENSIONS, false, "Lookup the extensions details");
		options.addOption(OPTION_SK_LOOKUP_QR, OPTION_LK_LOOKUP_QR, false, "Lookup the quality rules details");	
		options.addOption(OPTION_SK_AIPVERSION, OPTION_LK_AIPVERSION, true, "AIP Version (if not set, the latest version will be selected)");
		options.addOption(OPTION_SK_FILTEREXTVERSION, OPTION_LK_FILTEREXTVERSION, true, "Filter the extension versions : ALL or LAST (if not set, the last version will be selected)");
		return options;
	}
	
	
	/**
	 * Load the command line parameters
	 * 
	 * @throws ParseException
	 */
	protected void parseCmdLineParameters(String[] p_parameters) {
		logger.info("parsing command line ...");

		try {
			Options options = constructCmdLineOptions();
			CommandLineParser parser = new GnuParser();
			org.apache.commons.cli.CommandLine cmd = parser.parse(options, p_parameters);
			if (logger.isDebugEnabled()) {
				StringBuffer sb = new StringBuffer("  command line=");
				for (String arg : p_parameters) {
					sb.append(arg);
					sb.append(" ");
				}
				logger.debug(sb.toString());
			}
			// set only if value not null, else default value
			if (cmd.hasOption(OPTION_LK_LOOKUP_EXTENSIONS))
				this.extensionsDetailLookup = !"false".equals(cmd.getOptionValue(OPTION_LK_LOOKUP_EXTENSIONS));
			if (cmd.hasOption(OPTION_LK_LOOKUP_QR))
				this.qualityRuleDetailLookup = !"false".equals(cmd.getOptionValue(OPTION_LK_LOOKUP_QR));
			this.AIPVersion = cmd.getOptionValue(OPTION_LK_AIPVERSION);
			this.extensionVersionFilter = cmd.getOptionValue(OPTION_LK_FILTEREXTVERSION);

		} catch (org.apache.commons.cli.ParseException e) {
			logger.error("Error parsing command line : " + e.getMessage());
			printHelp(constructCmdLineOptions(), 80, "", "", 5, 3, true, System.out);
			System.exit(-1);
		}
		logger.info("parsing command line [OK]");			
		}	
	
	/**
	 * Write "help" to the provided OutputStream.
	 */
	public static void printHelp(final Options options, final int printedRowWidth, final String header,
			final String footer, final int spacesBeforeOption, final int spacesBeforeOptionDescription,
			final boolean displayUsage, final OutputStream out) {
		final String commandLineSyntax = "-lookupExtensionsDetails -lookupQualityRuleDetails -AIPVersion 8.2.5_1598 -filterExtensionsVersion LAST";
		final PrintWriter writer = new PrintWriter(out);
		final HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.printHelp(writer, printedRowWidth, commandLineSyntax, header, options, spacesBeforeOption,
				spacesBeforeOptionDescription, footer, displayUsage);
		writer.close();
	}	
	
	private String getFileName() {
		return "CAST_QualityModel_" + getAIPVersion() + ".xlsx";
	}

	private void extractQualityCube() {
		// quality rules for 1 business criteria
		String URI = null;
		String responseBody = null;

		XSSFWorkbook workbook = new XSSFWorkbook();
		XSSFSheet sheet = workbook.createSheet("Quality rules");
		String[] nameCells = null;

		if (this.qualityRuleDetailLookup) {
			nameCells = new String[] { "Type", "Parent name", "Version", "Quality rule id", "Quality rule name", "Critical",
					"Technologies", "Standard", "Href", };
		}	else {
		nameCells = new String[] { "Type", "Parent name", "Version", "Quality rule id", "Quality rule name", "Critical",
				"Technologies", "Href", };
		}
		FileOutputStream outputStream = null;
		JSONObject jsonobjectQR = null;
		Row row = sheet.createRow((short) 0);
		Cell cell;
		int headerColNum = 0;
		int rowNum = 1;
		for (String nc : nameCells) {
			cell = row.createCell(headerColNum++);
			cell.setCellValue(nc);
		}


		boolean bInputVersion = getAIPVersion() != null;
		try {
			// List of AIP versions
			URI = "https://technologies.castsoftware.com/rest/AIP/versions";			
			responseBody = executeRestAPIRequest(URI, null, null, "iso-8859-1", logger);
			JSONArray arrayVersions = checkJSONArrayResponseBodyErrors(responseBody);
			logger.info("AIP Plateform versions");
			for (int i = 0; i < arrayVersions.length(); i++) {
				JSONObject jsonobjectVersion = arrayVersions.getJSONObject(i);
				
				if (i == 0 && !bInputVersion) {
					logger.info(jsonobjectVersion.getString("name") + " (selected as last version)");
					this.AIPVersion = jsonobjectVersion.getString("name");
				} else if (bInputVersion && jsonobjectVersion.getString("name").equals(getAIPVersion())) {
					logger.info(jsonobjectVersion.getString("name") + " (selected as input version)");
				} else {
					logger.info(jsonobjectVersion.getString("name"));
				}
			}
			
			// List of quality rules for 1 version
			URI = "https://technologies.castsoftware.com/rest/AIP/versions/%2/quality-rules";
			URI = URI.replaceAll("%2", this.AIPVersion);
			responseBody = executeRestAPIRequest(URI, null, null, "iso-8859-1", logger);

			// Parsing the JSON structure
			JSONArray array = checkJSONArrayResponseBodyErrors(responseBody);
			// print headers
			//System.out.println("Type;Parent name;Version;Quality rule id;Quality rule name;Critical;Technologies;Href");
			for (int i = 0; i < array.length(); i++) {
				jsonobjectQR = array.getJSONObject(i);
				QualityRulesReportOutput qi = new QualityRulesReportOutput();
				qi.setType("quality-rules");
				qi.setParentType("platform");
				qi.setParentName("platform");
				qi.setParentVersion(this.AIPVersion);
				qi.setMetricName(jsonobjectQR.getString("name"));
				if (jsonobjectQR.getString("href") != null && jsonobjectQR.getString("href").indexOf("null") < 0)
					qi.setHref(jsonobjectQR.getString("href"));
				qi.setMetricId(jsonobjectQR.getInt("id"));
				qi.setCritical(jsonobjectQR.getBoolean("critical"));
				JSONArray arrayTech = jsonobjectQR.getJSONArray("technologyNames");
				for (int j = 0; j < arrayTech.length(); j++) {
					qi.addTechnology((String) arrayTech.getString(j));
				}
				//System.out.println(qi.toString());
				
				// TODO collect the technical criteria and business criteria
				if (isQualityRuleDetailLookup() && qi.getHref() != null && qi.getHref().indexOf("null") < 0 ) {
					responseBody =executeRestAPIRequest("https://technologies.castsoftware.com/rest/" + qi.getHref(), null, null, "iso-8859-1", logger);
					// Parsing the JSON structure
					JSONObject jsonObject = checkJSONObjectResponseBodyErrors(responseBody);
					JSONArray  jsonArrayBC = jsonObject.getJSONArray("businessCriteria");
					JSONArray  jsonArrayTC = jsonObject.getJSONArray("technicalCriteria");
					JSONArray  jsonArrayQS = jsonObject.getJSONArray("qualityStandards");
					for (int i1 = 0; i1 < jsonArrayQS.length() ; i1++) {
						qi.addStandard(jsonArrayQS.getJSONObject(i1).getString("standard") + "/" + jsonArrayQS.getJSONObject(i1).getString("id"));
					}
					//businessCriteria
					//technicalCriteria
					//qualityStandards
					//maxWeight
					//associatedValueName
					//description
					//output
					//rationale
					//remediation
					//total
					//technologies
					
				}
				// Data to Excel file
				int iCell = 0;
				row = sheet.createRow(rowNum++);
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getParentType());
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getParentName());				
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getParentVersion());
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getMetricId());
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getMetricName());
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.isCritical());
				cell = row.createCell(iCell++);
				cell.setCellValue(qi.getTechnologiesAsString());
				if (this.qualityRuleDetailLookup) {
					cell = row.createCell(iCell++);
					cell.setCellValue(qi.getStandardsAsString());
				}
				if (qi.getHref() != null) {
					cell = row.createCell(iCell++);
					cell.setCellValue("https://technologies.castsoftware.com/rest/" + qi.getHref());
				}
			}
			// list of extensions
			if (isExtensionsDetailLookup()) {
				responseBody = executeRestAPIRequest("https://technologies.castsoftware.com/rest/AIP/extensions", null, null, "iso-8859-1", logger);
				// Parsing the JSON structure
				array = checkJSONArrayResponseBodyErrors(responseBody);
				for (int j = 0; j < array.length(); j++) {
					JSONObject objectExt = array.getJSONObject(j);
					// if no quality model, we skip
					if (!objectExt.getBoolean("qualityModel"))
						continue;
					String href = objectExt.getString("href");
					responseBody = executeRestAPIRequest("https://technologies.castsoftware.com/rest/" + href + "/versions",
							null, null, "iso-8859-1", logger);
					// Parsing the JSON structure
					JSONArray arrayextVersion = checkJSONArrayResponseBodyErrors(responseBody);
					for (int k = 0; k < arrayextVersion.length(); k++) {
						JSONObject objectExtVersion = arrayextVersion.getJSONObject(k);
						responseBody = executeRestAPIRequest(
								"https://technologies.castsoftware.com/rest/" + href + "/versions/"
										+ objectExtVersion.getString("name") + "/quality-rules",
								null, null, "iso-8859-1", logger);
						JSONArray arrayQRExtension = checkJSONArrayResponseBodyErrors(responseBody);
						for (int k1 = 0; k1 < arrayQRExtension.length(); k1++) {
							JSONObject objectQRExt = arrayQRExtension.getJSONObject(k1);
							QualityRulesReportOutput qiext = new QualityRulesReportOutput();
							qiext.setType("quality-rules");
							qiext.setParentType("product extension");
							qiext.setParentName(objectExt.getString("name"));						
							qiext.setParentVersion(objectExtVersion.getString("name"));
							qiext.setMetricName(objectQRExt.getString("name"));
							if (objectQRExt.getString("href") != null && objectQRExt.getString("href").indexOf("null") < 0)
								qiext.setHref(objectQRExt.getString("href"));
							qiext.setMetricId(objectQRExt.getInt("id"));
							qiext.setCritical(objectQRExt.getBoolean("critical"));
							JSONArray arrayTechExt = objectQRExt.getJSONArray("technologyNames");
							for (int k2 = 0; k2 < arrayTechExt.length(); k2++) {
								qiext.addTechnology((String) arrayTechExt.getString(k2));
							}
							//System.out.println(qiext.toString());
							if (isQualityRuleDetailLookup() && qiext.getHref() != null && qiext.getHref().indexOf("null") < 0) {
								responseBody =executeRestAPIRequest("https://technologies.castsoftware.com/rest/" + qiext.getHref(), null, null, "iso-8859-1", logger);
								// Parsing the JSON structure
								JSONObject jsonObject = checkJSONObjectResponseBodyErrors(responseBody);
								JSONArray  jsonArrayBC = jsonObject.getJSONArray("businessCriteria");
								JSONArray  jsonArrayTC = jsonObject.getJSONArray("technicalCriteria");
								JSONArray  jsonArrayQS = jsonObject.getJSONArray("qualityStandards");
								for (int i1 = 0; i1 < jsonArrayQS.length() ; i1++) {
									qiext.addStandard(jsonArrayQS.getJSONObject(i1).getString("standard") + "/" + jsonArrayQS.getJSONObject(i1).getString("id"));
								}
							}	
							// Data to Excel file
							int iCell = 0;
							row = sheet.createRow(rowNum++);
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getParentType());
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getParentName());	
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getParentVersion());
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getMetricId());
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getMetricName());
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.isCritical());
							cell = row.createCell(iCell++);
							cell.setCellValue(qiext.getTechnologiesAsString());
							if (this.qualityRuleDetailLookup) {
								cell = row.createCell(iCell++);
								cell.setCellValue(qiext.getStandardsAsString());
							}
							if (qiext.getHref() != null) {
								cell = row.createCell(iCell++);
								cell.setCellValue("https://technologies.castsoftware.com/rest/" + qiext.getHref());						
							}
						}
						// we keep only the last version for each extension
						if (extensionVersionFilter == null || (extensionVersionFilter != null && FILTER_EXTENSION_VERSION_LAST.equals(extensionVersionFilter)) 
								|| (extensionVersionFilter != null && "".equals(extensionVersionFilter))) {
							break;
						} else ; // ALL extension versions will be extracted
						
					}
	
				}
			}
			outputStream = new FileOutputStream(getFileName());
			logger.info("Generating file " + getFileName() + " ...");
			workbook.write(outputStream);
			logger.info("Generating file " + getFileName() + " [OK]");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			logger.error("Error : " + e.getMessage());
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

	public boolean isQualityRuleDetailLookup() {
		return qualityRuleDetailLookup;
	}

	public void setQualityRuleDetailLookup(boolean qualityRuleDetailLookup) {
		this.qualityRuleDetailLookup = qualityRuleDetailLookup;
	}

	public boolean isExtensionsDetailLookup() {
		return extensionsDetailLookup;
	}

	public void setExtensionsDetailLookup(boolean extensionsDetailLookup) {
		this.extensionsDetailLookup = extensionsDetailLookup;
	}

	public String getAIPVersion() {
		return AIPVersion;
	}

	public void setAIPVersion(String aIPVersion) {
		AIPVersion = aIPVersion;
	}

	public String getExtensionVersionFilter() {
		return extensionVersionFilter;
	}

	public void setExtensionVersionFilter(String extensionVersionFilter) {
		this.extensionVersionFilter = extensionVersionFilter;
	}

	
	
	
	
}
