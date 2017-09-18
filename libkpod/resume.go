package libkpod

import (
	"github.com/kubernetes-incubator/cri-o/oci"
	"github.com/pkg/errors"
)

// ContainerResume resumes all processes in one or more paused containers.
func (c *ContainerServer) ContainerResume(container string) (string, error) {
	ctr, err := c.LookupContainer(container)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find container %s", container)
	}
	cStatus := c.runtime.ContainerStatus(ctr)
	if cStatus.Status != oci.ContainerStatePaused{
			return "", errors.Errorf( "%s is not paused", ctr.ID())
	}
	if  err := c.runtime.ContainerResume(ctr); err != nil {
		return "", errors.Wrapf(err, "failed to unpause container %s", ctr.ID())
	}
	return ctr.ID(), nil
}
