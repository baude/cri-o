package libpod

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/containers/storage"
	"github.com/docker/docker/pkg/stringid"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/ulule/deepcopier"
)

// ContainerState represents the current state of a container
type ContainerState int

const (
	// ContainerStateUnknown indicates that the container is in an error
	// state where information about it cannot be retrieved
	ContainerStateUnknown ContainerState = iota
	// ContainerStateConfigured indicates that the container has had its
	// storage configured but it has not been created in the OCI runtime
	ContainerStateConfigured ContainerState = iota
	// ContainerStateCreated indicates the container has been created in
	// the OCI runtime but not started
	ContainerStateCreated ContainerState = iota
	// ContainerStateRunning indicates the container is currently executing
	ContainerStateRunning ContainerState = iota
	// ContainerStateStopped indicates that the container was running but has
	// exited
	ContainerStateStopped ContainerState = iota
	// ContainerStatePaused indicates that the container has been paused
	ContainerStatePaused ContainerState = iota
)

// Container is a single OCI container
type Container struct {
	config *containerConfig

	pod         *Pod
	runningSpec *spec.Spec

	state *containerState

	// TODO move to storage.Locker from sync.Mutex
	valid   bool
	lock    sync.Mutex
	runtime *Runtime
}

// containerState contains the current state of the container
// It is stored as on disk in a per-boot directory
type containerState struct {
	// The current state of the running container
	State ContainerState `json:"state"`

	// The path to the JSON OCI runtime spec for this container
	ConfigPath string `json:"configPath,omitempty"`
	// RunDir is a per-boot directory for container content
	RunDir string `json:"runDir,omitempty"`

	// Mounted indicates whether the container's storage has been mounted
	// for use
	Mounted bool `json:"-"`
	// MountPoint contains the path to the container's mounted storage
	Mountpoint string `json:"mountPoint,omitempty"`

	// TODO: Save information about image used in container if one is used
	// TODO save start time, create time (create time in the containerConfig?)
}

// containerConfig contains all information that was used to create the
// container. It may not be changed once created.
// It is stored as an unchanging part of on-disk state
type containerConfig struct {
	Spec *spec.Spec `json:"spec"`
	ID   string     `json:"id"`
	Name string     `json:"name"`
	// RootfsFromImage indicates whether the container uses a root
	// filesystem from an image, or from a user-provided directory
	RootfsFromImage bool
	// Directory used as a root filesystem if not configured with an image
	RootfsDir string `json:"rootfsDir,omitempty"`
	// Information on the image used for the root filesystem
	RootfsImageID   string `json:"rootfsImageID,omitempty"`
	RootfsImageName string `json:"rootfsImageName,omitempty"`
	UseImageConfig  bool   `json:"useImageConfig"`
	// Whether to keep container STDIN open
	Stdin bool
	// Static directory for container content that will persist across
	// reboot
	StaticDir string `json:"staticDir"`
	// Pod the container belongs to
	Pod *string `json:"pod,omitempty"`
	// Shared namespaces with container
	SharedNamespaceCtr *string           `json:"shareNamespacesWith,omitempty"`
	SharedNamespaceMap map[string]string `json:"sharedNamespaces"`
}

// ID returns the container's ID
func (c *Container) ID() string {
	return c.config.ID
}

// Name returns the container's name
func (c *Container) Name() string {
	return c.config.Name
}

// Spec returns the container's OCI runtime spec
// The spec returned is the one used to create the container. The running
// spec may differ slightly as mounts are added based on the image
func (c *Container) Spec() *spec.Spec {
	spec := new(spec.Spec)
	deepcopier.Copy(c.config.Spec).To(spec)

	return spec
}

// State returns the current state of the container
func (c *Container) State() (ContainerState, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// TODO uncomment when working
	// if err := c.runtime.ociRuntime.updateContainerStatus(c); err != nil {
	// 	return ContainerStateUnknown, err
	// }

	return c.state.State, nil
}

// Make a new container
func newContainer(rspec *spec.Spec) (*Container, error) {
	if rspec == nil {
		return nil, errors.Wrapf(ErrInvalidArg, "must provide a valid runtime spec to create container")
	}

	ctr := new(Container)
	ctr.config = new(containerConfig)
	ctr.state = new(containerState)

	ctr.config.ID = stringid.GenerateNonCryptoID()
	ctr.config.Name = ctr.config.ID // TODO generate unique human-readable names

	ctr.config.Spec = new(spec.Spec)
	deepcopier.Copy(rspec).To(ctr.config.Spec)

	return ctr, nil
}

// Create container root filesystem for use
func (c *Container) setupStorage() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.valid {
		return errors.Wrapf(ErrCtrRemoved, "container %s is not valid", c.ID())
	}

	if c.state.State != ContainerStateConfigured {
		return errors.Wrapf(ErrCtrStateInvalid, "container %s must be in Configured state to have storage set up", c.ID())
	}

	// If we're configured to use a directory, perform that setup
	if !c.config.RootfsFromImage {
		// TODO implement directory-based root filesystems
		return ErrNotImplemented
	}

	// Not using a directory, so call into containers/storage
	return c.setupImageRootfs()
}

// Set up an image as root filesystem using containers/storage
func (c *Container) setupImageRootfs() error {
	// Need both an image ID and image name, plus a bool telling us whether to use the image configuration
	if c.config.RootfsImageID == "" || c.config.RootfsImageName == "" {
		return errors.Wrapf(ErrInvalidArg, "must provide image ID and image name to use an image")
	}

	// TODO SELinux mount label
	containerInfo, err := c.runtime.storageService.CreateContainerStorage(c.runtime.imageContext, c.config.RootfsImageName, c.config.RootfsImageID, c.config.Name, c.config.ID, "")
	if err != nil {
		return errors.Wrapf(err, "error creating container storage")
	}

	c.config.StaticDir = containerInfo.Dir
	c.state.RunDir = containerInfo.RunDir

	return nil
}

// Create creates a container in the OCI runtime
func (c *Container) Create() (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.valid {
		return errors.Wrapf(ErrCtrRemoved, "container %s is not valid", c.ID())
	}

	if c.state.State != ContainerStateConfigured {
		return errors.Wrapf(ErrCtrExists, "container %s has already been created in runtime", c.ID())
	}

	if !c.state.Mounted {
		return errors.Wrapf(ErrInternal, "container root filesystem is not mounted")
	}

	// If using containers/storage, mount the container
	if !c.config.RootfsFromImage {
		// TODO implemented directory-based root filesystems
		return ErrNotImplemented
	} else {
		mountPoint, err := c.runtime.storageService.StartContainer(c.ID())
		if err != nil {
			return errors.Wrapf(err, "error mounting storage for container %s", c.ID())
		}
		c.state.Mounted = true
		c.state.Mountpoint = mountPoint

		defer func() {
			if err != nil {
				if err2 := c.runtime.storageService.StopContainer(c.ID()); err2 != nil {
					logrus.Errorf("Error unmounting storage for container %s: %v", c.ID(), err2)
				}

				c.state.Mounted = false
				c.state.Mountpoint = ""
			}
		}()
	}

	// Make the OCI runtime spec we will use
	c.runningSpec = new(spec.Spec)
	deepcopier.Copy(c.config.Spec).To(c.runningSpec)
	c.runningSpec.Root.Path = c.state.Mountpoint

	// TODO Add annotation for start time to spec

	// Save the OCI spec to disk
	jsonPath := filepath.Join(c.state.RunDir, "config.json")
	fileJSON, err := json.Marshal(c.runningSpec)
	if err != nil {
		return errors.Wrapf(err, "error exporting runtime spec for container %s to JSON", c.ID())
	}
	if err := ioutil.WriteFile(jsonPath, fileJSON, 0644); err != nil {
		return errors.Wrapf(err, "error writing runtime spec JSON to file for container %s", c.ID())
	}
	c.state.ConfigPath = jsonPath

	// With the spec complete, do an OCI create
	// TODO set cgroup parent in a sane fashion
	if err := c.runtime.ociRuntime.createContainer(c, "/libpod_parent"); err != nil {
		return err
	}

	// TODO should flush this state to disk here
	c.state.State = ContainerStateCreated

	return nil
}

// Start starts a container
func (c *Container) Start() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.valid {
		return ErrCtrRemoved
	}

	// Container must be created or stopped to be started
	if !(c.state.State == ContainerStateCreated || c.state.State == ContainerStateStopped) {
		return errors.Wrapf(ErrCtrStateInvalid, "container %s must be in Created or Stopped state to be started", c.ID())
	}

	if err := c.runtime.ociRuntime.startContainer(c); err != nil {
		return err
	}

	// TODO should flush state to disk here
	c.state.State = ContainerStateRunning

	return nil
}

// Stop stops a container
func (c *Container) Stop() error {
	return ErrNotImplemented
}

// Kill sends a signal to a container
func (c *Container) Kill(signal uint) error {
	return ErrNotImplemented
}

// Exec starts a new process inside the container
// Returns fully qualified URL of streaming server for executed process
func (c *Container) Exec(cmd []string, tty bool, stdin bool) (string, error) {
	return "", ErrNotImplemented
}

// Attach attaches to a container
// Returns fully qualified URL of streaming server for the container
func (c *Container) Attach(stdin, tty bool) (string, error) {
	return "", ErrNotImplemented
}

// Mount mounts a container's filesystem on the host
// The path where the container has been mounted is returned
func (c *Container) Mount() (string, error) {
	return "", ErrNotImplemented
}

// Pause pauses a container
func (c *Container) Pause() error {
	return ErrNotImplemented
}

// Unpause unpauses a container
func (c *Container) Unpause() error {
	return ErrNotImplemented
}

// Export exports a container's root filesystem as a tar archive
// The archive will be saved as a file at the given path
func (c *Container) Export(path string) error {
	return ErrNotImplemented
}

// Commit commits the changes between a container and its image, creating a new
// image
// If the container was not created from an image (for example,
// WithRootFSFromPath will create a container from a directory on the system),
// a new base image will be created from the contents of the container's
// filesystem
func (c *Container) Commit() (*storage.Image, error) {
	return nil, ErrNotImplemented
}
