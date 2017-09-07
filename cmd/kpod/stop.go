package main

import (
	"fmt"
	"github.com/kubernetes-incubator/cri-o/libkpod"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"github.com/sirupsen/logrus"
	"os"
)

var (
	defaultTimeout int64 = 10
	stopFlags            = []cli.Flag{
		cli.Int64Flag{
			Name:  "timeout, t",
			Usage: "Seconds to wait for stop before killing the container",
			Value: defaultTimeout,
		},
	}
	stopDescription = "Stop one or more containers"
	stopCommand     = cli.Command{
		Name: "stop",
		Usage: "Stops one or more running containers.  The container name or ID can be used.  A timeout to forcibly" +
			" stop the container can also be set but defaults to 10 seconds otherwise.",
		Description: stopDescription,
		Flags:       stopFlags,
		Action:      stopCmd,
		ArgsUsage:   "CONTAINER-NAME",
	}
)

func stopCmd(c *cli.Context) error {
	args := c.Args()
	stopTimeout := c.Int64("timeout")
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
	hadError := false
	for _, container := range c.Args() {
		cid, err := server.ContainerStop(container, stopTimeout)
		if err != nil {
			hadError = true
			logrus.Error(err)
		} else {
			fmt.Println(cid)
		}
	}

	if hadError{
		os.Exit(1)
	}
	return nil
}
