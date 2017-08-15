package formats

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"text/template"
)

const JSONString string = "json"

// Writer interface for outputs
type Writer interface {
	Out() error
}

// JSONStructArray for JSON output
type JSONStructArray struct {
	Output []interface{}
}

// StdoutTemplateArray for Go template output
type StdoutTemplateArray struct {
	Output   []interface{}
	Template string
}

// JSONStruct for JSON output
type JSONStruct struct {
	Output interface{}
}

// StdoutTemplatefor Go template output
type StdoutTemplate struct {
	Output   interface{}
	Template string
}

// Should the next two funcs be combined?
// Out method for JSON Arrays
func (j JSONStructArray) Out() error {
	data, err := json.MarshalIndent(j.Output, "", "    ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	return nil
}

func (j JSONStruct) Out() error {
	data, err := json.MarshalIndent(j.Output, "", "    ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	return nil
}


// Out method for Go templates arrays
func (t StdoutTemplateArray) Out() error {
	tmpl, err := template.New("image").Parse(t.Template)
	if err != nil {
		return errors.Wrapf(err, "Template parsing error")
	}

	for _, img := range t.Output {
		err = tmpl.Execute(os.Stdout, img)
		if err != nil {
			return err
		}
		fmt.Println()
	}
	return nil
}

//Out method for Go templates
func (t StdoutTemplate) Out() error {
	fmt.Printf("%v\n", t.Output)
	tmpl, err := template.New("image").Parse(t.Template)
	if err != nil {
		return errors.Wrapf(err, "Template parsing error")
	}
	err = tmpl.Execute(os.Stdout, t.Output)
	fmt.Println()
	return nil
}
