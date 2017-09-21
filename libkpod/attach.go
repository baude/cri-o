package libkpod

import (
	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/pkg/errors"
	"fmt"
	"path/filepath"
	"os"
	"net"
	"golang.org/x/sys/unix"
	"io"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/remotecommand"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"github.com/kubernetes-incubator/cri-o/utils"
	//"strconv"
)

/* Sync with stdpipe_t in conmon.c */
const (
	AttachPipeStdin  = 1
	AttachPipeStdout = 2
	AttachPipeStderr = 3
)

// ContainerAttach attaches to a running container
func (c *ContainerServer) ContainerAttach(container string) (error) {
	ctr, err := c.LookupContainer(container)
	if err != nil {
		return errors.Wrapf(err, "failed to find container %s", container)
	}

	cStatus := c.runtime.ContainerStatus(ctr)
	if !(cStatus.Status == oci.ContainerStateRunning || cStatus.Status == oci.ContainerStateCreated) {
		return errors.Errorf("%s is not created or running", container)
	}

	resize := make(chan remotecommand.TerminalSize)

	AttachContainerSocket(ctr, resize)
	//if err != nil {
	//	return errors.Wrapf(err, "container %s", ctr.ID())
	//}

	close(resize)
	c.ContainerStateToDisk(ctr)

	return nil
}


// Attach to the containers socket
func AttachContainerSocket(ctr *oci.Container, resize <-chan remotecommand.TerminalSize) error {
	inputStream := os.Stdin
	outputStream := os.Stdout
	errorStream := os.Stderr
	//tty,err := strconv.ParseBool(ctr.State().Annotations["io.kubernetes.cri-o.TTY"])
	//if err != nil {
	//	return errors.Errorf("unable to parse annotations in %", ctr.ID)
	//}


	//c := ss.runtimeServer.GetContainer(containerID)

	//if c == nil {
	//	return fmt.Errorf("could not find container %q", containerID)
	//}

	//if err := ss.runtimeServer.Runtime().UpdateStatus(c); err != nil {
	//	return err
	//}

	//cState := ss.runtimeServer.Runtime().ContainerStatus(c)
	//if !(cState.Status == oci.ContainerStateRunning || cState.Status == oci.ContainerStateCreated) {
	//	return fmt.Errorf("container is not created or running")
	//}

	controlPath := filepath.Join(ctr.BundlePath(), "ctl")
	controlFile, err := os.OpenFile(controlPath, unix.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open container ctl file: %v", err)
	}

	kubecontainer.HandleResizing(resize, func(size remotecommand.TerminalSize) {
		logrus.Infof("Got a resize event: %+v", size)
		_, err := fmt.Fprintf(controlFile, "%d %d %d\n", 1, size.Height, size.Width)
		if err != nil {
			logrus.Infof("Failed to write to control file to resize terminal: %v", err)
		}
	})
	attachSocketPath := filepath.Join("/var/run/crio", ctr.ID(), "attach")
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: attachSocketPath, Net: "unixpacket"})
	if err != nil {
		return fmt.Errorf("failed to connect to container %s attach socket: %v", ctr.ID(), err)
	}
	defer conn.Close()

	receiveStdout := make(chan error)
	if outputStream != nil || errorStream != nil {
		go func() {
			receiveStdout <- redirectResponseToOutputStreams(outputStream, errorStream, conn)
		}()
	}

	stdinDone := make(chan error)
	go func() {
		var err error
		if inputStream != nil {
			_, err = utils.CopyDetachable(conn, inputStream, nil)
			conn.CloseWrite()
		}
		stdinDone <- err
	}()

	select {
	case err := <-receiveStdout:
		return err
	case err := <-stdinDone:
		if _, ok := err.(utils.DetachError); ok {
			return nil
		}
		if outputStream != nil || errorStream != nil {
			return <-receiveStdout
		}
	}

	return nil
}

func redirectResponseToOutputStreams(outputStream, errorStream io.Writer, conn io.Reader) error {
	var err error
	buf := make([]byte, 8192+1) /* Sync with conmon STDIO_BUF_SIZE */

	for {
		nr, er := conn.Read(buf)
		if nr > 0 {
			var dst io.Writer
			if buf[0] == AttachPipeStdout {
				dst = outputStream
			} else if buf[0] == AttachPipeStderr {
				dst = errorStream
			} else if buf[0] == AttachPipeStdin {
				fmt.Printf("!!\n")
			} else
			 {
				logrus.Infof("Got unexpected attach type %+d", buf[0])
			}

			if dst != nil {
				fmt.Printf("##A\n")
				nw, ew := dst.Write(buf[1:nr])
				fmt.Printf("##B\n")
				if ew != nil {
					err = ew
					break
				}
				if nr != nw+1 {
					err = io.ErrShortWrite
					break
				}
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}

	return err
}