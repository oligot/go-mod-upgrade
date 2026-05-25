package module

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RewriteImportsInProject recursively updates import statements in all .go files from oldPath to newPath.
func RewriteImportsInProject(oldPath, newPath string) error {
	oldStr1 := fmt.Sprintf(`"%s"`, oldPath)
	newStr1 := fmt.Sprintf(`"%s"`, newPath)
	oldStr2 := fmt.Sprintf(`"%s/`, oldPath)
	newStr2 := fmt.Sprintf(`"%s/`, newPath)

	return filepath.Walk(".", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		sContent := string(content)
		modified := false
		// Replace subpackages first to avoid double replacement
		if strings.Contains(sContent, oldStr2) {
			sContent = strings.ReplaceAll(sContent, oldStr2, newStr2)
			modified = true
		}
		if strings.Contains(sContent, oldStr1) {
			sContent = strings.ReplaceAll(sContent, oldStr1, newStr1)
			modified = true
		}

		if modified {
			return os.WriteFile(path, []byte(sContent), info.Mode())
		}
		return nil
	})
}
