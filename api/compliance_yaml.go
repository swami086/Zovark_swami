package main

import (
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// complianceRulesFile mirrors config/compliance_rules.yaml (MITRE → CMMC / HIPAA).
type complianceRulesFile struct {
	CMMC struct {
		TechniqueControls map[string][]string `yaml:"technique_controls"`
	} `yaml:"cmmc"`
	HIPAA struct {
		TechniqueSections map[string][]string `yaml:"technique_sections"`
	} `yaml:"hipaa"`
}

func loadComplianceRulesYAML() *complianceRulesFile {
	path := strings.TrimSpace(os.Getenv("ZOVARK_COMPLIANCE_RULES_PATH"))
	if path == "" {
		for _, p := range []string{"config/compliance_rules.yaml", "../config/compliance_rules.yaml"} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				path = p
				break
			}
		}
	}
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out complianceRulesFile
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}

func normalizeTechniqueID(t string) string {
	t = strings.TrimSpace(strings.ToUpper(t))
	return t
}

// mapYAMLCompliance builds runtime CMMC / HIPAA hints from observed MITRE IDs and compliance_rules.yaml.
func mapYAMLCompliance(techniques []string, rules *complianceRulesFile) map[string]interface{} {
	out := map[string]interface{}{
		"source":                "compliance_rules.yaml",
		"cmmc_control_ids":      []string{},
		"hipaa_section_refs":    []string{},
		"per_technique":         []map[string]interface{}{},
		"yaml_file_loaded":      rules != nil,
	}
	if rules == nil {
		return out
	}

	cmmcSet := map[string]struct{}{}
	hipaaSet := map[string]struct{}{}
	per := make([]map[string]interface{}, 0)

	for _, raw := range techniques {
		tid := normalizeTechniqueID(raw)
		if tid == "" {
			continue
		}
		cc := rules.CMMC.TechniqueControls[tid]
		hs := rules.HIPAA.TechniqueSections[tid]
		for _, x := range cc {
			cmmcSet[x] = struct{}{}
		}
		for _, x := range hs {
			hipaaSet[x] = struct{}{}
		}
		if len(cc) > 0 || len(hs) > 0 {
			per = append(per, map[string]interface{}{
				"technique_id":       tid,
				"cmmc_controls":      cc,
				"hipaa_section_refs": hs,
			})
		}
	}

	cmmcList := make([]string, 0, len(cmmcSet))
	for x := range cmmcSet {
		cmmcList = append(cmmcList, x)
	}
	sort.Strings(cmmcList)
	hipaaList := make([]string, 0, len(hipaaSet))
	for x := range hipaaSet {
		hipaaList = append(hipaaList, x)
	}
	sort.Strings(hipaaList)

	out["cmmc_control_ids"] = cmmcList
	out["hipaa_section_refs"] = hipaaList
	out["per_technique"] = per
	return out
}
