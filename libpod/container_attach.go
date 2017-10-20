package libpod

import (
	"strconv"
	"path/filepath"
	"fmt"
	"os"
	"io"

	"golang.org/x/sys/unix"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/remotecommand"
	"github.com/docker/docker/pkg/term"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"github.com/sirupsen/logrus"
	"net"
	"github.com/kubernetes-incubator/cri-o/utils"
)


/* Sync with stdpipe_t in conmon.c */
const (
	AttachPipeStdin  = 1
	AttachPipeStdout = 2
	AttachPipeStderr = 3
)

// attachContainerSocket connects to the container's attach socket and deals with the IO
func (c *Container) attachContainerSocket(resize <-chan remotecommand.TerminalSize, noStdIn bool, detachKeys []byte) error {
	inputStream := os.Stdin
	outputStream := os.Stdout
	errorStream := os.Stderr

	defer inputStream.Close()
	tty, err := strconv.ParseBool(c.runningSpec.Annotations["io.kubernetes.cri-o.TTY"])
	if err != nil {
		return errors.Wrapf(err, "unable to parse annotations in %s", c.ID)
	}
	if !tty {
		return errors.Errorf("no tty available for %s", c.ID())
	}

	oldTermState, err := term.SaveState(inputStream.Fd())

	if err != nil {
		return errors.Wrapf(err, "unable to save terminal state")
	}

	defer term.RestoreTerminal(inputStream.Fd(), oldTermState)

	// Put both input and output into raw
	if !noStdIn {
		term.SetRawTerminal(inputStream.Fd())
	}

	controlPath := filepath.Join(c.containerDir, "ctl")
	controlFile, err := os.OpenFile(controlPath, unix.O_WRONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "failed to open container ctl file: %v")
	}

	kubecontainer.HandleResizing(resize, func(size remotecommand.TerminalSize) {
		logrus.Debug("Got a resize event: %+v", size)
		_, err := fmt.Fprintf(controlFile, "%d %d %d\n", 1, size.Height, size.Width)
		if err != nil {
			logrus.Warn("Failed to write to control file to resize terminal: %v", err)
		}
	})
	attachSocketPath := filepath.Join("/var/run/crio", c.ID(), "attach")
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: attachSocketPath, Net: "unixpacket"})
	if err != nil {
		return errors.Wrapf(err, "failed to connect to container's attach socket: %v")
	}
	defer conn.Close()

	receiveStdoutError := make(chan error)
	if outputStream != nil || errorStream != nil {
		go func() {
			receiveStdoutError <- redirectResponseToOutputStreams(outputStream, errorStream, conn)
		}()
	}

	stdinDone := make(chan error)
	go func() {
		var err error
		if inputStream != nil && !noStdIn {
			_, err = utils.CopyDetachable(conn, inputStream, detachKeys)
			conn.CloseWrite()
		}
		stdinDone <- err
	}()

	select {
	case err := <-receiveStdoutError:
		return err
	case err := <-stdinDone:
		if _, ok := err.(utils.DetachError); ok {
			return nil
		}
		if outputStream != nil || errorStream != nil {
			return <-receiveStdoutError
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
			switch buf[0] {
			case AttachPipeStdout:
				dst = outputStream
			case AttachPipeStderr:
				dst = errorStream
			default:
				logrus.Infof("Got unexpected attach type %+d", buf[0])
			}

			if dst != nil {
				nw, ew := dst.Write(buf[1:nr])
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
