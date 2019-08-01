package com.castsoftware.uc.qualitycubereport;

import java.util.ArrayList;
import java.util.List;

public class QualityRulesReportOutput implements Cloneable {
	private static final String OUTPUT_SEPARATOR = ";";
	
	private int metricId;
	private String metricName;
	// quality-rules / technical-criteria / quality-distributions
	private String type;
	private boolean critical;
	
	// platform / extension
	private String parentType;
	private String parentName;
	private String parentVersion;	
	

	private List<String> listTechnologies = new ArrayList<String> ();
	private List<String> listStandards = new ArrayList<String> ();
	
	private Double threshold1 = -1d;
	private Double threshold2 = -1d;
	private Double threshold3 = -1d;
	private Double threshold4 = -1d;
	private String restHref;
	

	private int technicalCriterionId;
	private String technicalCriterionName;
	private int weight;
	private int businessCriterionId;
	private String businessCriterionName;
	private int weightTechnicalCriterion;
	
	public int getMetricId() {
		return metricId;
	}
	public void setMetricId(int metricId) {
		this.metricId = metricId;
	}
	public String getMetricName() {
		return metricName;
	}
	public void setMetricName(String metricName) {
		this.metricName = metricName;
	}
	public boolean isCritical() {
		return critical;
	}
	public void setCritical(boolean critical) {
		this.critical = critical;
	}
	public Double getThreshold1() {
		return threshold1;
	}
	public void setThreshold1(Double threshold1) {
		this.threshold1 = threshold1;
	}
	public Double getThreshold2() {
		return threshold2;
	}
	public void setThreshold2(Double threshold2) {
		this.threshold2 = threshold2;
	}
	public Double getThreshold3() {
		return threshold3;
	}
	public void setThreshold3(Double threshold3) {
		this.threshold3 = threshold3;
	}
	public Double getThreshold4() {
		return threshold4;
	}
	public void setThreshold4(Double threshold4) {
		this.threshold4 = threshold4;
	}
	public int getTechnicalCriterionId() {
		return technicalCriterionId;
	}
	public void setTechnicalCriterionId(int technicalCriterionId) {
		this.technicalCriterionId = technicalCriterionId;
	}
	public String getTechnicalCriterionName() {
		return technicalCriterionName;
	}
	public void setTechnicalCriterionName(String technicalCriterionName) {
		this.technicalCriterionName = technicalCriterionName;
	}
	public int getWeight() {
		return weight;
	}
	public void setWeight(int weight) {
		this.weight = weight;
	}
	public int getBusinessCriterionId() {
		return businessCriterionId;
	}
	public void setBusinessCriterionId(int businessCriterionId) {
		this.businessCriterionId = businessCriterionId;
	}
	public String getBusinessCriterionName() {
		return businessCriterionName;
	}
	public void setBusinessCriterionName(String businessCriterionName) {
		this.businessCriterionName = businessCriterionName;
	}
	public int getWeightTechnicalCriterion() {
		return weightTechnicalCriterion;
	}
	public void setWeightTechnicalCriterion(int weightTechnicalCriterion) {
		this.weightTechnicalCriterion = weightTechnicalCriterion;
	}

	public String getFullRestHref() {
		if (restHref != null)
			return "https://technologies.castsoftware.com/rest/"+restHref;
		return null;
	}
	
	public String getRestHref() {
		return restHref;
	}
	public void setHref(String restHref) {
		this.restHref = restHref;
	}
	
	public String getHref() {
		if (metricId != 0)
			return "https://technologies.castsoftware.com/rules?s="+metricId+"|qualityrules|"+metricId;
		return null;
	}	
	
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}

	public void addTechnology(String technology)  {
		listTechnologies.add(technology);
	}
	
	public void addStandard(String standard)  {
		listStandards.add(standard);
	}
	
	public List<String> getTechnologie()  {
		return listTechnologies;
	}

	public String getParentVersion() {
		return parentVersion;
	}
	public void setParentVersion(String parentVersion) {
		this.parentVersion = parentVersion;
	}

	
	public String getParentType() {
		return parentType;
	}
	public void setParentType(String parentType) {
		this.parentType = parentType;
	}
	public String getParentName() {
		return parentName;
	}
	public void setParentName(String parentName) {
		this.parentName = parentName;
	}
	
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(parentType);
		sb.append(OUTPUT_SEPARATOR);
		sb.append(parentName);
		sb.append(OUTPUT_SEPARATOR);		
		sb.append(parentVersion);
		sb.append(OUTPUT_SEPARATOR);
		sb.append(metricId);
		sb.append(OUTPUT_SEPARATOR);
		sb.append(metricName);
		sb.append(OUTPUT_SEPARATOR);
		sb.append(critical);		
		sb.append(OUTPUT_SEPARATOR);
		sb.append(getTechnologiesAsString());
		sb.append(OUTPUT_SEPARATOR);
		sb.append("https://technologies.castsoftware.com/rules?s="+metricId+"|qualityrules|"+metricId);
		sb.append(OUTPUT_SEPARATOR);
		sb.append("https://technologies.castsoftware.com/rest/"+restHref);	
		return sb.toString();
	}	
	
	public String getTechnologiesAsString() {
		if (listTechnologies==null)
			return "";
		StringBuffer sb = new StringBuffer();
		int i = 0;
		for (String techno: listTechnologies) {
			sb.append(techno);
			if (i < listTechnologies.size() - 1) {
				sb.append("/");
			}
			i++;
		}
		return sb.toString();
	}
	
	public String getStandardsAsString() {
		if (listStandards==null)
			return "";
		StringBuffer sb = new StringBuffer();
		int i = 0;
		for (String std: listStandards) {
			sb.append(std);
			if (i < listStandards.size() - 1) {
				sb.append("#");
			}
			i++;
		}
		return sb.toString();		
	}
	
	
	public List<String> getListStandards() {
		return listStandards;
	}
	public void setListStandards(List<String> listStandards) {
		this.listStandards = listStandards;
	}
	public Object clone() throws CloneNotSupportedException{  
		return super.clone();  
	}  
	
}

