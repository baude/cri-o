package main

import (
	"fmt"

	"github.com/containers/storage/pkg/archive"
	"github.com/kubernetes-incubator/cri-o/cmd/kpod/formats"
	"github.com/kubernetes-incubator/cri-o/libkpod"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

type diffJSONOutput struct {
	Changed []string `json:"changed,omitempty"`
	Added   []string `json:"added,omitempty"`
	Deleted []string `json:"deleted,omitempty"`
}

type changed struct {
	Changed []string `json:"changed"`
}

type added struct {
	Added []string `json:"added"`
}

type deleted struct {
	Deleted []string `json:"deleted"`
}

type diffOutputParams struct {
	Change archive.ChangeType
	Path   string
}

type stdoutStruct struct {
	output []diffOutputParams
}

func (so stdoutStruct) Out() error {
	for _, d := range so.output {
		fmt.Printf("%s %s\n", d.Change, d.Path)
	}
	return nil
}

var (
	diffFlags = []cli.Flag{
		cli.BoolFlag{
			Name:   "archive",
			Usage:  "Save the diff as a tar archive",
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "format",
			Usage: "Change the output format.",
		},
	}
	diffDescription = fmt.Sprint(`Displays changes on a container or image's filesystem.  The
	container or image will be compared to its parent layer`)

	diffCommand = cli.Command{
		Name:        "diff",
		Usage:       "Inspect changes on container's file systems",
		Description: diffDescription,
		Flags:       diffFlags,
		Action:      diffCmd,
		ArgsUsage:   "ID-NAME",
	}
)

func diffToGeneric(params diffJSONOutput) []interface{} {
	var genericParams []interface{}
	genericParams = append(genericParams, params)

	// We want our JSON output to format correctly.  Empty arrays should appear
	// as [] rather than null
	if len(params.Changed) < 1 {
		var emptyChanges changed
		emptyChanges.Changed = make([]string, 0)
		genericParams = append(genericParams, emptyChanges)
	}

	if len(params.Added) < 1 {
		var emptyAdds added
		emptyAdds.Added = make([]string, 0)
		genericParams = append(genericParams, emptyAdds)
	}

	if len(params.Deleted) < 1 {
		var emptyDeletes deleted
		emptyDeletes.Deleted = make([]string, 0)
		genericParams = append(genericParams, emptyDeletes)
	}
	return genericParams
}

func formatJSON(output []diffOutputParams) (diffJSONOutput, error) {
	jsonStruct := diffJSONOutput{}
	for _, output := range output {
		switch output.Change {
		case archive.ChangeModify:
			jsonStruct.Changed = append(jsonStruct.Changed, output.Path)
		case archive.ChangeAdd:
			jsonStruct.Added = append(jsonStruct.Added, output.Path)
		case archive.ChangeDelete:
			jsonStruct.Deleted = append(jsonStruct.Deleted, output.Path)
		default:
			return jsonStruct, errors.Errorf("output kind %q not recognized", output.Change.String())
		}
	}

	return jsonStruct, nil
}

func diffCmd(c *cli.Context) error {
	if len(c.Args()) != 1 {
		return errors.Errorf("container, layer, or image name must be specified: kpod diff [options [...]] ID-NAME")
	}
	config, err := getConfig(c)
	if err != nil {
		return errors.Wrapf(err, "could not get config")
	}

	server, err := libkpod.New(config)
	if err != nil {
		return errors.Wrapf(err, "could not get container server")
	}

	to := c.Args().Get(0)
	changes, err := server.GetDiff("", to)
	if err != nil {
		return errors.Wrapf(err, "could not get changes for %q", to)
	}

	diffOutput := []diffOutputParams{}
	outputFormat := c.String("format")

	for _, change := range changes {

		params := diffOutputParams{
			Change: change.Kind,
			Path:   change.Path,
		}
		diffOutput = append(diffOutput, params)
	}

	var out formats.Writer

	if outputFormat != "" {
		switch outputFormat {
		case formats.JSONString:
			data, err := formatJSON(diffOutput)
			if err != nil {
				return err
			}
			out = formats.JSONstruct{Output: diffToGeneric(data)}
		default:
			return errors.New("only valid format for diff is 'json'")
		}
	} else {
		out = stdoutStruct{output: diffOutput}
	}
	formats.Writer(out).Out()

	return nil
}
