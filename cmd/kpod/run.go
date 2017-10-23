package main

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/kubernetes-incubator/cri-o/libpod"
	"github.com/sirupsen/logrus"
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

	createImage := runtime.NewImage(createConfig.image)

	if !createImage.HasImageLocal() {
		// The image wasnt found by the user input'd name or its fqname
		// Pull the image
		fmt.Printf("Trying to pull %s...", createImage.PullName)
		createImage.Pull()
	}

	runtimeSpec, err := createConfigToOCISpec(createConfig)
	if err != nil {
		return err
	}

	imageName, err := createImage.GetFQName()
	if err != nil {
		return err
	}
	logrus.Debug("imageName is ", imageName)

	imageID, err := createImage.GetImageID()
	if err != nil {
		return err
	}
	logrus.Debug("imageID is ", imageID)

	ctr, err := runtime.NewContainer(runtimeSpec, libpod.WithRootFSFromImage(imageID, imageName, false),
		libpod.WithStdin())
	if err != nil {
		return err
	}

	logrus.Debug("new container created ", ctr.ID())
	if err := ctr.Create(); err != nil{
		return err
	}
	logrus.Debug("container storage created for ", ctr.ID())

	if c.String("cid-file") != ""{
		libpod.WriteFile(ctr.ID(), c.String("cid-file"))
		return nil
	}
	// Start the container
	if err := ctr.Start(); err != nil{
		return errors.Wrapf(err, "unable to start container ", ctr.ID())
	}
	logrus.Debug("started container ", ctr.ID())
	if createConfig.tty {
		logrus.Debug("trying to attach to the container %s", ctr.ID())
		if err := ctr.Attach(false, ""); err != nil {
			return errors.Wrapf(err, "unable to attach to container %s", ctr.ID())
		}
	}else {
		fmt.Printf("%s\n", ctr.ID())
	}




	return nil
}
