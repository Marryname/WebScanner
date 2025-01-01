package vulnscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Template struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Solution    string                 `json:"solution"`
	References  []string               `json:"references"`
	Matchers    []Matcher              `json:"matchers"`
	Variables   map[string]string      `json:"variables"`
	Conditions  map[string]interface{} `json:"conditions"`
}

type Matcher struct {
	Type    string   `json:"type"`
	Part    string   `json:"part"`
	Words   []string `json:"words,omitempty"`
	Regex   []string `json:"regex,omitempty"`
	Status  []int    `json:"status,omitempty"`
	Binary  bool     `json:"binary,omitempty"`
	Inverse bool     `json:"inverse,omitempty"`
}

type TemplateManager struct {
	templates map[string]*Template
}

func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*Template),
	}
}

func (tm *TemplateManager) LoadTemplates(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("读取模板文件失败: %v", err)
			}

			var tmpl Template
			if err := json.Unmarshal(data, &tmpl); err != nil {
				return fmt.Errorf("解析模板文件失败: %v", err)
			}

			tm.templates[tmpl.ID] = &tmpl
		}

		return nil
	})
}
