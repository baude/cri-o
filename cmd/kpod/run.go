package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/kubernetes-incubator/cri-o/libpod"
)

var runDescription = "Runs a command in a new container from the given image"

var runCommand = cli.Command{
	Name:        "run",
	Usage:       "run a command in a new container",
	Description: runDescription,
	Flags:       createFlags,
	Action:      runCmd,
	ArgsUsage:   "IMAGE [COMMAND [ARG...]]",
}

func runCmd(c *cli.Context) error {
	if len(c.Args()) != 1 {
		return errors.Errorf("must specify name of image to create from")
	}
	if err := validateFlags(c, createFlags); err != nil {
		return err
	}
	runtime, err := libpod.NewRuntime()
	if err != nil {
		return errors.Wrapf(err, "error creating libpod runtime")
	}

	createConfig, err := parseCreateOpts(c, runtime)
	if err != nil {
		return err
	}

	runtimeSpec, err := createConfigToOCISpec(createConfig)
	if err != nil {
		return err
	}

	ctr, err := runtime.NewContainer(runtimeSpec)
	if err != nil {
		return err
	}
	createImage := runtime.NewImage(createConfig.image)

	if !createImage.HasImageLocal() {
		// The image wasnt found by the user input'd name or its fqname
		// Pull the image
		fmt.Printf("Trying to pull %s...", createImage.PullName)
		createImage.Pull()
	}

	runtimeSpec, err = createConfigToOCISpec(createConfig)
	if err != nil {
		return err
	}

	imageName, err := createImage.GetFQName()
	if err != nil {
		return err
	}

	imageID, err := createImage.GetImageID()
	if err != nil {
		return err
	}

	ctr, err = runtime.NewContainer(runtimeSpec, libpod.WithRootFSFromImage(imageID, imageName, false) )
	if err != nil {
		return err
	}

	if err := ctr.Create(); err != nil{
		return err
	}

	if c.String("cid-file") != ""{
		libpod.WriteFile(ctr.ID(), c.String("cid-file"))
		return nil
	}

	fmt.Printf("%s\n", ctr.ID())



	return nil
}
