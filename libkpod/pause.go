package libkpod

import (
	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/pkg/errors"
)

// ContainerPause pauses a running container with a grace period (i.e., timeout).
func (c *ContainerServer) ContainerPause(container string) (string, error) {
	ctr, err := c.LookupContainer(container)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find container %s", container)
	}
	cStatus := c.runtime.ContainerStatus(ctr)
	if cStatus.Status != oci.ContainerStateRunning{
		return "", errors.Errorf("%s cannot be paused. it is not running", ctr.ID())
	}
	if  err := c.runtime.ContainerPause(ctr); err != nil {
		return "", errors.Wrapf(err, "failed to pause container %s", ctr.ID())
	}
	return ctr.ID(), nil
}
