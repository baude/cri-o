package main

import (
	"fmt"
	"os"

	"github.com/kubernetes-incubator/cri-o/libkpod"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	resumeFlags            = []cli.Flag{
	}
	resumeDescription = `
   kpod unpause

   unpause all the processes in one or more running containers.  You can specify the container
   by name or ID.
`

	resumeCommand = cli.Command{
		Name:        "unpause",
		Usage:       "Unpause all processor in one or more paused containers",
		Description: resumeDescription,
		Flags:       resumeFlags,
		Action:      resumeCmd,
		ArgsUsage:   "CONTAINER-NAME [CONTAINER-NAME ...]",
	}
)

func resumeCmd(c *cli.Context) error {
	args := c.Args()
	if len(args) < 1 {
		return errors.Errorf("you must provide at least one container name or id")
	}
	config, err := getConfig(c)
	if err != nil {
		return errors.Wrapf(err, "could not get config")
	}
	server, err := libkpod.New(config)
	if err != nil {
		return errors.Wrapf(err, "could not get container server")
	}
	defer server.Shutdown()
	err = server.Update()
	if err != nil {
		return errors.Wrapf(err, "could not update list of containers")
	}
	var lastError error
	for _, container := range c.Args() {
		cid, err := server.ContainerResume(container)
		if err != nil {
			if lastError != nil {
				fmt.Fprintln(os.Stderr, lastError)
			}
			lastError = errors.Wrapf(err, "failed to unpause container %v", container)
		} else {
			fmt.Println(cid)
		}
	}

	return lastError
}
