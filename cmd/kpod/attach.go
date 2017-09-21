package main

import (
	"github.com/kubernetes-incubator/cri-o/libkpod"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	attachFlags            = []cli.Flag{
		cli.StringFlag{
			Name:  "detach-keys",
			Usage: "Override the key sequence for detaching a container. Format is a single character [a-Z] or ctrl-<value> where <value> is one of: a-z, @, ^, [, , or _.",

		},
		cli.BoolFlag{
			Name: "no-stdin",
			Usage: "Do not attach STDIN. The default is false.",
		},
		cli.BoolFlag{
			Name: "sig-proxy",
			Usage: "Proxy all received signals to the process (non-TTY mode only). SIGCHLD, SIGKILL, and SIGSTOP are not proxied. The default is true.",
		},
	}
	attachDescription = `
   kpod attach


`
	attachCommand = cli.Command{
		Name:        "attach",
		Usage:       "attach to a running container",
		Description: attachDescription,
		Flags:       attachFlags,
		Action:      attachCmd,
		ArgsUsage:   "CONTAINER-NAME | CONTAINER-NAME ",
	}
)

func attachCmd(c *cli.Context) error {
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
	err = server.ContainerAttach(c.Args()[0])
	return err

}
