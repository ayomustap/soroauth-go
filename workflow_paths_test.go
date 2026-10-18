package soroauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPathFilteredWorkflowsIncludeTheirOwnPath(t *testing.T) {
	const workflowDir = ".github/workflows"

	workflows, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading workflow directory: %v", err)
	}

	for _, workflow := range workflows {
		name := workflow.Name()
		if workflow.IsDir() || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}

		t.Run(name, func(t *testing.T) {
			path := filepath.ToSlash(filepath.Join(workflowDir, name))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading workflow: %v", err)
			}

			var document yaml.Node
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatalf("parsing workflow YAML: %v", err)
			}
			if len(document.Content) == 0 {
				return
			}

			triggers := mappingValue(document.Content[0], "on")
			if triggers == nil {
				t.Fatal("workflow has no on trigger")
			}
			if triggers.Kind != yaml.MappingNode {
				return
			}

			for index := 0; index+1 < len(triggers.Content); index += 2 {
				eventName := triggers.Content[index].Value
				paths := mappingValue(triggers.Content[index+1], "paths")
				if paths == nil {
					continue
				}
				if paths.Kind != yaml.SequenceNode {
					t.Errorf("event %q paths must be a YAML list", eventName)
					continue
				}

				includesWorkflow := false
				for _, pattern := range paths.Content {
					if pattern.Value == path {
						includesWorkflow = true
						break
					}
				}
				if !includesWorkflow {
					t.Errorf("event %q paths must include %q", eventName, path)
				}
			}
		})
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}
