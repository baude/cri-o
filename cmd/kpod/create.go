package main

import (
	"fmt"

	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	pb "k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"
	"strings"

	"github.com/docker/go-units"
	"github.com/kubernetes-incubator/cri-o/libpod"
	"golang.org/x/sys/unix"
	"strconv"
)

type createResourceConfig struct {
	blkioDevice       []string // blkio-weight-device
	blkioWeight       uint16   // blkio-weight
	cpuPeriod         uint64   // cpu-period
	cpuQuota          int64    // cpu-quota
	cpuRtPeriod       uint64   // cpu-rt-period
	cpuRtRuntime      int64    // cpu-rt-runtime
	cpuShares         uint64   // cpu-shares
	cpus              string   // cpus
	cpusetCpus        string
	cpusetMems        string   // cpuset-mems
	deviceReadBps     []string // device-read-bps
	deviceReadIops    []string // device-read-iops
	deviceWriteBps    []string // device-write-bps
	deviceWriteIops   []string // device-write-iops
	disableOomKiller  bool     // oom-kill-disable
	kernelMemory      int64    // kernel-memory
	memory            int64    //memory
	memoryReservation int64    // memory-reservation
	memorySwap        int64    //memory-swap
	memorySwapiness   uint64   // memory-swappiness
	oomScoreAdj       int      //oom-score-adj
	pidsLimit         int64    // pids-limit
	shmSize           string
	ulimit            []string //ulimit

	//cpuCount          int64 // cpu-count
	//cpusetNames       string
	//cpuFile           string
}

type createConfig struct {
	//additionalGroups []int64
	args           []string
	capAdd         []string // cap-add
	capDrop        []string // cap-drop
	cidFile        string
	cgroupParent   string // cgroup-parent
	command        []string
	detach         bool         // detach
	devices        []*pb.Device // device
	dnsOpt         []string     //dns-opt
	dnsSearch      []string     //dns-search
	dnsServers     []string     //dns
	entrypoint     string       //entrypoint
	env            []string     //env
	expose         []string     //expose
	groupAdd       []uint32     // group-add
	hostname       string       //hostname
	image          string
	interactive    bool              //interactive
	ip6Address     string            //ipv6
	ipAddress      string            //ip
	labels         map[string]string //label
	linkLocalIP    []string          // link-local-ip
	logDriver      string            // log-driver
	logDriverOpt   []string          // log-opt
	macAddress     string            //mac-address
	name           string            //name
	network        string            //network
	networkAlias   []string          //network-alias
	nsIPC          string            // ipc
	nsNet          string            //net
	nsPID          string            //pid
	nsUser         string
	pod            string   //pod
	privileged     bool     //privileged
	publish        []string //publish
	publishAll     bool     //publish-all
	readOnlyRootfs bool     //read-only
	resources      createResourceConfig
	rm             bool              //rm
	securityOpts   []string          //security-opt
	sigProxy       bool              //sig-proxy
	stopSignal     string            // stop-signal
	stopTimeout    int64             // stop-timeout
	storageOpts    []string          //storage-opt
	sysctl         map[string]string //sysctl
	tmpfs          []string          // tmpfs
	tty            bool              //tty
	user           uint32            //user
	group          uint32            // group
	volumes        []string          //volume
	volumesFrom    []string          //volumes-from
	workDir        string            //workdir
}

var createDescription = "Creates a new container from the given image or" +
	" storage and prepares it for running the specified command. The" +
	" container ID is then printed to stdout. You can then start it at" +
	" any time with the kpod start <container_id> command. The container" +
	" will be created with the initial state 'created'."

var createCommand = cli.Command{
	Name:        "create",
	Usage:       "create but do not start a container",
	Description: createDescription,
	Flags:       createFlags,
	Action:      createCmd,
	ArgsUsage:   "IMAGE [COMMAND [ARG...]]",
}

func createCmd(c *cli.Context) error {
	// TODO should allow user to create based off a directory on the host not just image
	// Need CLI support for this
	//if len(c.Args()) != 1 {
	//	return errors.Errorf("must specify name of image to create from")
	//}
	if err := validateFlags(c, createFlags); err != nil {
		return err
	}
	//runtime, err := getRuntime(c)
	runtime, err := libpod.NewRuntime()
	if err != nil {
		return errors.Wrapf(err, "error creating libpod runtime")
	}

	createConfig, err := parseCreateOpts(c, runtime)
	if err != nil {
		return err
	}

	// Deal with the image after all the args have been checked
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
	fmt.Println(imageName)
	imageID, err := createImage.GetImageID()
	if err != nil {
		return err
	}
	fmt.Println(imageID)
	ctr, err := runtime.NewContainer(runtimeSpec, libpod.WithRootFSFromImage(imageID, imageName, false) )
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

/* The following funcs should land in parse.go */
//
//
func stringSlicetoUint32Slice(inputSlice []string) ([]uint32, error) {
	var outputSlice []uint32
	for _, v := range inputSlice {
		u, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return outputSlice, err
		}
		outputSlice = append(outputSlice, uint32(u))
	}
	return outputSlice, nil
}

// Parses CLI options related to container creation into a config which can be
// parsed into an OCI runtime spec
func parseCreateOpts(c *cli.Context, runtime *libpod.Runtime) (*createConfig, error) {
	var command []string
	var memoryLimit, memoryReservation, memorySwap, memoryKernel int64
	var blkioWeight uint16
	var env []string
	var uid, gid uint32
	sysctl := make(map[string]string)
	labels := make(map[string]string)

	image := c.Args()[0]

	if len(c.Args()) < 1 {
		return nil, errors.Errorf("you just provide an image name")
	}
	if len(c.Args()) > 1 {
		command = c.Args()[1:]
	}

	if len(c.StringSlice("env")) > 0 {
		for _, inputEnv := range c.StringSlice("env") {
			env = append(env, inputEnv)
		}
	} else {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm")
	}

	if len(c.StringSlice("sysctl")) > 0 {
		for _, inputSysctl := range c.StringSlice("sysctl") {
			values := strings.Split(inputSysctl, "=")
			sysctl[values[0]] = values[1]
		}
	}

	groupAdd, err := stringSlicetoUint32Slice(c.StringSlice("group-add"))
	if err != nil {
		return &createConfig{}, errors.Wrapf(err, "invalid value for groups provided")
	}

	if c.String("user") != "" {
		// We need to mount the imagefs and get the uid/gid
		// For now, user zeros
		uid = 0
		gid = 0
	}

	if c.String("memory") != "" {
		memoryLimit, err = units.RAMInBytes(c.String("memory"))
		if err != nil {
			return nil, errors.Wrapf(err, "invalid value for memory")
		}
	}
	if c.String("memory-reservation") != "" {
		memoryReservation, err = units.RAMInBytes(c.String("memory-reservation"))
		if err != nil {
			return nil, errors.Wrapf(err, "invalid value for memory-reservation")
		}
	}
	if c.String("memory-swap") != "" {
		memorySwap, err = units.RAMInBytes(c.String("memory-swap"))
		if err != nil {
			return nil, errors.Wrapf(err, "invalid value for memory-swap")
		}
	}
	if c.String("kernel-memory") != "" {
		memoryKernel, err = units.RAMInBytes(c.String("kernel-memory"))
		if err != nil {
			return nil, errors.Wrapf(err, "invalid value for kernel-memory")
		}
	}
	if c.String("blkio-weight") != "" {
		u, err := strconv.ParseUint(c.String("blkio-weight"), 10, 16)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid value for blkio-weight")
		}
		blkioWeight = uint16(u)
	}

	//var blkioWeightDevices []spec.LinuxWeightDevice
	//if len(c.StringSlice("blkio-weight-device")) > 0{
	//	for _, i := range(c.StringSlice("blkio-weight-device")) {
	//		wd, err := validateweightDevice(i)
	//		if err != nil {
	//			return nil, errors.Wrapf(err, "invalid values for blkio-weight-device")
	//		}
	//		wdStat := unix.Stat_t{}
	//		_ = unix.Stat(wd.path, &wdStat)
	//		major := unix.Major(wdStat.Rdev)
	//		minor := unix.Minor(wdStat.Rdev)
	//		_ = blkioLeafWeight
	//			//spec.LinuxWeightDevice{devices.Major()}
	//		//fmt.Println("Major:",uint64(stat.Rdev/256), "Minor:",uint64(stat.Rdev%256))
	//		//blkioWeightDevices = append(blkioWeightDevices, lwd)
	//	}
	//}

	config := &createConfig{
		capAdd:         c.StringSlice("cap-add"),
		capDrop:        c.StringSlice("cap-drop"),
		cgroupParent:   c.String("cgroup-parent"),
		command:        command,
		detach:         c.Bool("detach"),
		dnsOpt:         c.StringSlice("dns-opt"),
		dnsSearch:      c.StringSlice("dns-search"),
		dnsServers:     c.StringSlice("dns"),
		entrypoint:     c.String("entrypoint"),
		env:            env,
		expose:         c.StringSlice("env"),
		groupAdd:       groupAdd,
		hostname:       c.String("hostname"),
		image:          image,
		interactive:    c.Bool("interactive"),
		ip6Address:     c.String("ipv6"),
		ipAddress:      c.String("ip"),
		labels:         labels,
		linkLocalIP:    c.StringSlice("link-local-ip"),
		logDriver:      c.String("log-driver"),
		logDriverOpt:   c.StringSlice("log-opt"),
		macAddress:     c.String("mac-address"),
		name:           c.String("name"),
		network:        c.String("network"),
		networkAlias:   c.StringSlice("network-alias"),
		nsIPC:          c.String("ipc"),
		nsNet:          c.String("net"),
		nsPID:          c.String("pid"),
		pod:            c.String("pod"),
		privileged:     c.Bool("privileged"),
		publish:        c.StringSlice("publish"),
		publishAll:     c.Bool("publish-all"),
		readOnlyRootfs: c.Bool("read-only"),
		resources: createResourceConfig{
			blkioWeight: blkioWeight,
			blkioDevice: c.StringSlice("blkio-weight-device"),
			cpuShares:   c.Uint64("cpu-shares"),
			//cpuCount:          c.Int64("cpu-count"),
			cpuPeriod:         c.Uint64("cpu-period"),
			cpusetCpus:        c.String("cpu-period"),
			cpusetMems:        c.String("cpuset-mems"),
			cpuQuota:          c.Int64("cpu-quota"),
			cpuRtPeriod:       c.Uint64("cpu-rt-period"),
			cpuRtRuntime:      c.Int64("cpu-rt-runtime"),
			cpus:              c.String("cpus"),
			deviceReadBps:     c.StringSlice("device-read-bps"),
			deviceReadIops:    c.StringSlice("device-read-iops"),
			deviceWriteBps:    c.StringSlice("device-write-bps"),
			deviceWriteIops:   c.StringSlice("device-write-iops"),
			disableOomKiller:  c.Bool("oom-kill-disable"),
			memory:            memoryLimit,
			memoryReservation: memoryReservation,
			memorySwap:        memorySwap,
			memorySwapiness:   c.Uint64("memory-swapiness"),
			kernelMemory:      memoryKernel,
			oomScoreAdj:       c.Int("oom-score-adj"),

			pidsLimit: c.Int64("pids-limit"),
			ulimit:    c.StringSlice("ulimit"),
		},
		rm:           c.Bool("rm"),
		securityOpts: c.StringSlice("security-opt"),
		//shmSize: c.String("shm-size"),
		sigProxy:    c.Bool("sig-proxy"),
		stopSignal:  c.String("stop-signal"),
		stopTimeout: c.Int64("stop-timeout"),
		storageOpts: c.StringSlice("storage-opt"),
		sysctl:      sysctl,
		tmpfs:       c.StringSlice("tmpfs"),
		tty:         c.Bool("tty"), //
		user:        uid,
		group:       gid,
		//userns: c.String("userns"),
		volumes:     c.StringSlice("volume"),
		volumesFrom: c.StringSlice("volumes-from"),
		workDir:     c.String("workdir"),
	}

	return config, nil
}

// Parses information needed to create a container into an OCI runtime spec
func createConfigToOCISpec(config *createConfig) (*spec.Spec, error) {

	blkio, err := config.CreateBlockIO()
	if err != nil {
		return &spec.Spec{}, err
	}

	spec := &spec.Spec{
		Version: spec.Version,
		Process: &spec.Process{
			Terminal: config.tty,
			User: spec.User{
				UID:            config.user,     //uint32
				GID:            config.group,    //uin32
				AdditionalGids: config.groupAdd, //[]uint32
				//Username //string  <- No input
			},
			Args:         config.command, // command plus all args
			Env:          config.env,
			Cwd: config.workDir,
			Capabilities: &spec.LinuxCapabilities{
			// No match from user input for any of these

			// Bounding []string
			// Effective []string
			// Inheritable []string
			// Permitted []string
			// Ambient []string

			},
			// Rlimits []PosixRlimit // Where does this come from
			// Type string
			// Hard uint64
			// Limit uint64
			// NoNewPrivileges bool // No user input for this
			// ApparmorProfile string // No user input for this
			OOMScoreAdj: &config.resources.oomScoreAdj,
			// Selinuxlabel
		},
		Root: &spec.Root{
			//Path: path to rootfs // is this workdir ?
			Readonly: config.readOnlyRootfs,
		},
		Hostname: config.hostname,
		// Mounts
		Hooks: &spec.Hooks{},
		//Annotations
		Linux: &spec.Linux{
			// UIDMappings
			// GIDMappings
			Sysctl: config.sysctl,
			Resources: &spec.LinuxResources{
				// Devices []LinuxDeviceCgroup
				Memory: &spec.LinuxMemory{
					Limit:       &config.resources.memory,
					Reservation: &config.resources.memoryReservation,
					Swap:        &config.resources.memorySwap,
					Kernel:      &config.resources.kernelMemory,
					// kerneltcp <-- nothing for this one
					Swappiness:       &config.resources.memorySwapiness,
					DisableOOMKiller: &config.resources.disableOomKiller,
				},
				CPU: &spec.LinuxCPU{
					Shares:          &config.resources.cpuShares,
					Quota:           &config.resources.cpuQuota,
					Period:          &config.resources.cpuPeriod,
					RealtimeRuntime: &config.resources.cpuRtRuntime,
					RealtimePeriod:  &config.resources.cpuRtPeriod,
					Cpus:            config.resources.cpus,
					Mems:            config.resources.cpusetMems,
				},
				Pids: &spec.LinuxPids{
					Limit: config.resources.pidsLimit,
				},
				BlockIO: &blkio,
				//HugepageLimits:
				Network: &spec.LinuxNetwork{
				// ClassID *uint32
				// Priorites []LinuxInterfacePriority
				},
			},
			//CgroupsPath:
			//Namespaces: []LinuxNamespace
			//Devices
			Seccomp: &spec.LinuxSeccomp{
			// DefaultAction:
			// Architectures
			// Syscalls:
			},
			// RootfsPropagation
			// MaskedPaths
			// ReadonlyPaths:
			// MountLabel
			// IntelRdt
		},
	}
	return spec, nil
}

func getStatFromPath(path string) unix.Stat_t {
	s := unix.Stat_t{}
	_ = unix.Stat(path, &s)
	return s
}

func makeThrottleArray(throttleInput []string) ([]spec.LinuxThrottleDevice, error) {
	var ltds []spec.LinuxThrottleDevice
	for _, i := range throttleInput {
		t, err := validateBpsDevice(i)
		if err != nil {
			return []spec.LinuxThrottleDevice{}, err
		}
		ltd := spec.LinuxThrottleDevice{}
		ltd.Rate = t.rate
		ltdStat := getStatFromPath(t.path)
		ltd.Major = int64(unix.Major(ltdStat.Rdev))
		ltd.Minor = int64(unix.Major(ltdStat.Rdev))
		ltds = append(ltds, ltd)
	}
	return ltds, nil

}

func (c *createConfig) CreateBlockIO() (spec.LinuxBlockIO, error) {
	bio := spec.LinuxBlockIO{}
	bio.Weight = &c.resources.blkioWeight
	if len(c.resources.blkioDevice) > 0 {
		var lwds []spec.LinuxWeightDevice
		for _, i := range c.resources.blkioDevice {
			wd, err := validateweightDevice(i)
			if err != nil {
				return bio, errors.Wrapf(err, "invalid values for blkio-weight-device")
			}
			wdStat := getStatFromPath(wd.path)
			lwd := spec.LinuxWeightDevice{
				Weight: &wd.weight,
			}
			lwd.Major = int64(unix.Major(wdStat.Rdev))
			lwd.Minor = int64(unix.Minor(wdStat.Rdev))
			lwds = append(lwds, lwd)
		}
	}
	if len(c.resources.deviceReadBps) > 0 {
		readBps, err := makeThrottleArray(c.resources.deviceReadBps)
		if err != nil {
			return bio, err
		}
		bio.ThrottleReadBpsDevice = readBps
	}
	if len(c.resources.deviceWriteBps) > 0 {
		writeBpds, err := makeThrottleArray(c.resources.deviceWriteBps)
		if err != nil {
			return bio, err
		}
		bio.ThrottleWriteBpsDevice = writeBpds
	}
	if len(c.resources.deviceReadIops) > 0 {
		readIops, err := makeThrottleArray(c.resources.deviceReadIops)
		if err != nil {
			return bio, err
		}
		bio.ThrottleReadIOPSDevice = readIops
	}
	if len(c.resources.deviceWriteIops) > 0 {
		writeIops, err := makeThrottleArray(c.resources.deviceWriteIops)
		if err != nil {
			return bio, err
		}
		bio.ThrottleWriteIOPSDevice = writeIops
	}

	return bio, nil
}
