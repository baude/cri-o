package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"

	"github.com/containers/storage"
	libkpodimage "github.com/kubernetes-incubator/cri-o/libkpod/image"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"strings"
)

type imageOutputParams struct {
	ID        string        `json:"id"`
	Name      string        `json:"names"`
	Digest    digest.Digest `json:"digest"`
	CreatedAt string        `json:"created"`
	Size      string        `json:"size"`
}

var outputTypes = []string{"json"}

var (
	imagesFlags = []cli.Flag{
		cli.BoolFlag{
			Name:  "quiet, q",
			Usage: "display only image IDs",
		},
		cli.BoolFlag{
			Name:  "noheading, n",
			Usage: "do not print column headings",
		},
		cli.BoolFlag{
			Name:  "no-trunc, notruncate",
			Usage: "do not truncate output",
		},
		cli.BoolFlag{
			Name:  "digests",
			Usage: "show digests",
		},
		cli.StringFlag{
			Name:  "template",
			Usage: "pretty-print images using a Go template. will override --quiet",
		},
		cli.StringFlag{
			Name:  "filter, f",
			Usage: "filter output based on conditions provided (default [])",
		},
		//https://github.com/urfave/cli/issues/620
		cli.StringFlag{
			Name:  "format",
			Usage: "Output in a structured format",
		},
	}

	imagesDescription = "lists locally stored images."
	imagesCommand     = cli.Command{
		Name:        "images",
		Usage:       "list images in local storage",
		Description: imagesDescription,
		Flags:       imagesFlags,
		Action:      imagesCmd,
		ArgsUsage:   "",
	}
)


type Writer interface {
	Out() error
}

type JSONStruct struct {
	output []imageOutputParams
}

type StdoutStruct struct {
	output []imageOutputParams
	truncate, digests, quiet, noheading bool
}

type StdoutTemplateStruct struct {
	output []imageOutputParams
	template string
}

func (j JSONStruct) Out() error{
	data, err := json.MarshalIndent(j.output, "", "    ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	return nil
}

func (so StdoutStruct) Out() error {
	if len(so.output) > 0 && !so.noheading && !so.quiet{
		outputHeader(so.truncate, so.digests)
	}
	lastID := ""
	for _, img := range so.output{
		if so.quiet{
			if lastID == img.ID {
				continue// quiet should not show the same ID multiple times.
			}
			fmt.Printf("%-64s\n", img.ID)
			continue
		}
		if so.truncate {
			fmt.Printf("%-20.12s %-56s", img.ID, img.Name)
		} else {
			fmt.Printf("%-64s %-56s", img.ID, img.Name)
		}

		if so.digests {
			fmt.Printf(" %-64s", img.Digest)
		}
		fmt.Printf(" %-22s %s\n", img.CreatedAt, img.Size)

		}
	return nil
}

func (t StdoutTemplateStruct) Out() error{
	for _, img := range t.output {
		tmpl, err := template.New("image").Parse(t.template)
		if err != nil {
			return errors.Wrapf(err, "Template parsing error")
		}
		err = tmpl.Execute(os.Stdout, img)
		if err != nil {
			return err
		}
		fmt.Println()
	}
	return nil
}

func checkOutputType(outputFormat string) error {
	for _, ot := range(outputTypes){
		if ot == outputFormat{
			return nil
		}
	}
	return fmt.Errorf("%s is not a valid output type.  Choose from '%s'", outputFormat, strings.Join(outputTypes, ","))
}

func imagesCmd(c *cli.Context) error {
	config, err := getConfig(c)
	if err != nil {
		return errors.Wrapf(err, "Could not get config")
	}
	store, err := getStore(config)
	if err != nil {
		return err
	}

	quiet := false
	if c.IsSet("quiet") {
		quiet = c.Bool("quiet")
	}
	noheading := false
	if c.IsSet("noheading") {
		noheading = c.Bool("noheading")
	}
	truncate := true
	if c.IsSet("no-trunc") {
		truncate = !c.Bool("no-trunc")
	}
	digests := false
	if c.IsSet("digests") {
		digests = c.Bool("digests")
	}
	templateString := ""
	hasTemplate := false
	if c.IsSet("template") {
		templateString = c.String("template")
		hasTemplate = true
	}
	var outputFormat = ""
	if c.IsSet("format") {
		outputFormat = c.String("format")
		err := checkOutputType(outputFormat)
		if err != nil{
			return err
		}

	}
	name := ""
	if len(c.Args()) == 1 {
		name = c.Args().Get(0)
	} else if len(c.Args()) > 1 {
		return errors.New("'buildah images' requires at most 1 argument")
	}

	var params *libkpodimage.FilterParams
	if c.IsSet("filter") {
		params, err = libkpodimage.ParseFilter(store, c.String("filter"))
		if err != nil {
			return errors.Wrapf(err, "error parsing filter")
		}
	} else {
		params = nil
	}

	imageList, err := libkpodimage.GetImagesMatchingFilter(store, params, name)
	if err != nil {
		return errors.Wrapf(err, "could not get list of images matching filter")
	}
	//if len(imageList) > 0 && !noheading && !quiet && !hasTemplate {
	//	outputHeader(truncate, digests)
	//}

	return outputImages(store, imageList, templateString, hasTemplate, truncate, digests, quiet, outputFormat, noheading)
}

func outputHeader(truncate, digests bool) {
	if truncate {
		fmt.Printf("%-20s %-56s ", "IMAGE ID", "IMAGE NAME")
	} else {
		fmt.Printf("%-64s %-56s ", "IMAGE ID", "IMAGE NAME")
	}

	if digests {
		fmt.Printf("%-71s ", "DIGEST")
	}

	fmt.Printf("%-22s %s\n", "CREATED AT", "SIZE")
}

func outputImages(store storage.Store, images []storage.Image, templateString string, hasTemplate, truncate, digests, quiet bool, outputFormat string, noheading bool) error {
	imageOutput := []imageOutputParams{}

	for _, img := range images {
		createdTime := img.Created

		name := ""
		if len(img.Names) > 0 {
			name = img.Names[0]
		}

		info, digest, size, _ := libkpodimage.InfoAndDigestAndSize(store, img)
		if info != nil {
			createdTime = info.Created
		}
/*
		if quiet {
			fmt.Printf("%-64s\n", img.ID)
			// We only want to print each id once
			break
		}
*/
		params := imageOutputParams{
			ID:        img.ID,
			Name:      name,
			Digest:    digest,
			CreatedAt: createdTime.Format("Jan 2, 2006 15:04"),
			Size:      libkpodimage.FormattedSize(size),
		}
		imageOutput = append(imageOutput, params)
	}

	var out Writer

	if hasTemplate {
		out = StdoutTemplateStruct{output: imageOutput, template: templateString}
	} else if outputFormat != ""{
		switch outputFormat{
		case "json":
			out = JSONStruct{output:imageOutput}
		default:
			//Placeholder ... this should be caught earlier.
			return fmt.Errorf("You must choose from the list of supported output formats")
		}
	} else{
		out = StdoutStruct{output:imageOutput, digests:digests, truncate:truncate, quiet:quiet, noheading:noheading}
	}

	Writer(out).Out()

	return nil
}


