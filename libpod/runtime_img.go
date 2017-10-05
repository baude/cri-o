package libpod

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"os"

	cp "github.com/containers/image/copy"
	dockerarchive "github.com/containers/image/docker/archive"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/docker/tarfile"
	"github.com/containers/image/manifest"
	ociarchive "github.com/containers/image/oci/archive"
	"github.com/containers/image/pkg/sysregistries"
	"github.com/containers/image/signature"
	is "github.com/containers/image/storage"
	"github.com/containers/image/transports"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	"github.com/kubernetes-incubator/cri-o/libpod/common"
	digest "github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"net"
)

// Runtime API

const (
	// DefaultRegistry is a prefix that we apply to an image name
	// to check docker hub first for the image
	DefaultRegistry = "docker://"
)

var (
	// DockerArchive is the Transport we prepend to an image name
	// when saving to docker-archive
	DockerArchive = dockerarchive.Transport.Name()
	// OCIArchive is the Transport we prepend to an image name
	// when saving to oci-archive
	OCIArchive     = ociarchive.Transport.Name()
	TransportNames = [...]string{DefaultRegistry, DockerArchive, OCIArchive, "ostree:", "dir:"}
)

// CopyOptions contains the options given when pushing or pulling images
type CopyOptions struct {
	// Compression specifies the type of compression which is applied to
	// layer blobs.  The default is to not use compression, but
	// archive.Gzip is recommended.
	Compression archive.Compression
	// DockerRegistryOptions encapsulates settings that affect how we
	// connect or authenticate to a remote Registry to which we want to
	// push the image.
	common.DockerRegistryOptions
	// SigningOptions encapsulates settings that control whether or not we
	// strip or add signatures to the image when pushing (uploading) the
	// image to a Registry.
	common.SigningOptions

	// SigningPolicyPath this points to a alternative signature policy file, used mainly for testing
	SignaturePolicyPath string
}
type DecomposedImage struct {
	Registry    string
	ImageName   string
	Tag         string
	HasRegistry bool
	Transport   string
}

func (k *KpodImage) assembleFqName() string {
	return fmt.Sprintf("%s/%s:%s", k.Registry, k.ImageName, k.Tag)
}

func (k *KpodImage) assembleFqNameTransport() string {
	return fmt.Sprintf("%s%s/%s:%s", k.Transport, k.Registry, k.ImageName, k.Tag)
}

type KpodImage struct {
	Name          string
	ID            string
	fqname        string
	hasImageLocal bool
	Runtime
	Registry       string
	ImageName      string
	Tag            string
	HasRegistry    bool
	Transport      string
	beenDecomposed bool
	PullName       string
}

func (r *Runtime) NewImage(name string) KpodImage {
	return KpodImage{
		Name:    name,
		Runtime: *r,
	}
}

func (k *KpodImage) GetImageID() (string, error) {
	//ref, err := istorage.Transport.ParseStoreReference(r.storageImageServer.store, imageID)
	//store, err := k.Runtime.GetStorageService(&k.Runtime)
	//if err != nil{
	//	return err
	//}
	if k.ID != "" {
		return k.ID, nil
	}
	image, _ := k.GetFQName()
	img, err := k.Runtime.GetImage(image)
	if err != nil {
		return "", err
	}
	//ref, err := is.Transport.ParseStoreReference(k.Runtime.store, image)
	//if err != nil {
	//	return "", err
	//}
	//imgRef, err := ref.NewImage(nil)
	//if err != nil {
	//	return ""err
	//}
	//fmt.Println(imgRef.OCIConfig())
	return img.ID, nil
}

func (k *KpodImage) GetFQName() (string, error) {
	// Check if the fqname has already been found
	if k.fqname != "" {
		return k.fqname, nil
	}
	err := k.Decompose()
	if err != nil {
		return "", err
	}
	k.fqname = k.assembleFqName()
	return k.fqname, nil
}

func (k *KpodImage) findImageOnRegistry() error {
	searchRegistries, err := GetRegistries()

	if err != nil {
		return errors.Wrapf(err, " the image name '%s' is incomplete.", k.Name)
	}

	for _, searchRegistry := range searchRegistries {
		k.Registry = searchRegistry
		err = k.GetManifest()
		if err == nil {
			k.fqname = k.assembleFqName()
			return nil

		}
		//pullRef, err := alltransports.ParseImageName(k.assembleFqNameTransport())
		//if err != nil {
		//	return errors.Errorf("unable to parse '%s'", k.assembleFqName())
		//}
		// trying getting this manifest pullRef.DockerReference().String()
		//imageSource, err := pullRef.NewImageSource(nil)
		//if err != nil {
		//	return errors.Errorf("unable to create new image source")
		//}
		//_, _, err = imageSource.GetManifest()
		//if err == nil {
		//	k.fqname = k.assembleFqName()
		//	return nil
		//}
	}
	return errors.Errorf("unable to find image on any configured registries")

}

func (k *KpodImage) GetManifest() error {
	pullRef, err := alltransports.ParseImageName(k.assembleFqNameTransport())
	if err != nil {
		return errors.Errorf("unable to parse '%s'", k.assembleFqName())
	}
	imageSource, err := pullRef.NewImageSource(nil)
	if err != nil {
		return errors.Errorf("unable to create new image source")
	}
	_, _, err = imageSource.GetManifest()
	if err == nil {
		return nil
	}
	return err

}

func stringInSlice(s string, sl []string) bool {
	for _, i := range sl {
		if i == s {
			return true
		}
	}
	return false
}

func (k *KpodImage) Decompose() error {
	k.beenDecomposed = true
	k.Transport = "docker://"
	decomposeName := k.Name
	for _, transport := range TransportNames {
		if strings.HasPrefix(k.Name, transport) {
			k.Transport = transport
			decomposeName = strings.Replace(k.Name, transport, "", -1)
			break
		}
	}
	if k.Transport == "dir:" {
		return nil
	}
	var imageError = fmt.Sprintf("unable to parse '%s'\n", k.Name)
	imgRef, err := reference.Parse(decomposeName)
	if err != nil {
		return errors.Wrapf(err, imageError)
	}
	tagged, isTagged := imgRef.(reference.NamedTagged)
	k.Tag = "latest"
	if isTagged {
		k.Tag = tagged.Tag()
	}
	k.HasRegistry = true
	registry := reference.Domain(imgRef.(reference.Named))
	if registry == "" {
		k.HasRegistry = false
	}
	k.ImageName = reference.Path(imgRef.(reference.Named))

	// account for image names with directories in them like
	// umohnani/get-started:part1
	if k.HasRegistry {
		k.Registry = registry
		k.fqname = k.assembleFqName()
		k.PullName = k.assembleFqName()

		registries, err := getRegistries()
		if err != nil {
			return nil
		}
		if stringInSlice(k.Registry, registries) {
			return nil
		} else {
			// We need to check if the registry name is legit
			_, err = net.LookupAddr(k.Registry)
			if err == nil {
				return nil
			}
			// Combine the Registry and Image Name together and blank out the Registry Name
			k.ImageName = fmt.Sprintf("%s/%s", k.Registry, k.ImageName)
			k.Registry = ""
		}
	}
	// No Registry means we check the globals registries configuration file
	// and assemble a list of candidate sources to try
	//searchRegistries, err := GetRegistries()
	err = k.findImageOnRegistry()
	k.PullName = k.assembleFqName()
	if err != nil {
		return errors.Wrapf(err, " the image name '%s' is incomplete.", k.Name)
	}
	return nil
}

func (k *KpodImage) HasImageLocal() bool {
	_, err := k.Runtime.GetImage(k.Name)
	if err == nil {
		return true
	}
	fqname, _ := k.GetFQName()

	_, err = k.Runtime.GetImage(fqname)
	if err == nil {
		return true
	}
	return false
}

func (k *KpodImage) HasLatest() (bool, error) {
	if !k.HasImageLocal() {
		return false, nil
	}
	fqname, err := k.GetFQName()
	if err != nil {
		return false, err
	}
	pullRef, err := alltransports.ParseImageName(fqname)
	if err != nil {
		return false, err
	}
	_, _, err = pullRef.(types.ImageSource).GetManifest()
	if err != nil {
		return false, err
	}
	return false, nil
}

func (k *KpodImage) Pull() error {
	// If the image hasn't been decomposed yet
	if !k.beenDecomposed {
		err := k.Decompose()
		if err != nil {
			return err
		}
	}
	k.Runtime.PullImage(k.PullName, false, k.Runtime.config.SignaturePolicyPath, os.Stdout)
	return nil
}

func GetRegistries() ([]string, error) {
	registryConfigPath := ""
	envOverride := os.Getenv("REGISTRIES_CONFIG_PATH")
	if len(envOverride) > 0 {
		registryConfigPath = envOverride
	}
	searchRegistries, err := sysregistries.GetRegistries(&types.SystemContext{SystemRegistriesConfPath: registryConfigPath})
	if err != nil {
		return nil, errors.Errorf("unable to parse the registries.conf file")
	}
	return searchRegistries, nil
}

func GetInsecureRegistries() ([]string, error) {
	registryConfigPath := ""
	envOverride := os.Getenv("REGISTRIES_CONFIG_PATH")
	if len(envOverride) > 0 {
		registryConfigPath = envOverride
	}
	registries, err := sysregistries.GetInsecureRegistries(&types.SystemContext{SystemRegistriesConfPath: registryConfigPath})
	if err != nil {
		return nil, errors.Errorf("unable to parse the registries.conf file")
	}
	return registries, nil
}

func getRegistries() ([]string, error) {
	var r []string
	registries, err := GetRegistries()
	if err != nil {
		return r, err
	}
	insecureRegistries, err := GetInsecureRegistries()
	if err != nil {
		return r, err
	}
	r = append(registries, insecureRegistries...)
	return r, nil
}

// Image API

// ImageFilterParams contains the filter options that may be given when outputting images
type ImageFilterParams struct {
	Dangling         string
	Label            string
	BeforeImage      time.Time
	SinceImage       time.Time
	ReferencePattern string
	ImageName        string
	ImageInput       string
}

// ImageFilter is a function to determine whether an image is included in
// command output. Images to be outputted are tested using the function. A true
// return will include the image, a false return will exclude it.
type ImageFilter func(*storage.Image, *types.ImageInspectInfo) bool

// PullImage pulls an image from configured registries
// By default, only the latest Tag (or a specific Tag if requested) will be
// pulled. If allTags is true, all tags for the requested image will be pulled.
// Signature validation will be performed if the Runtime has been appropriately
// configured
func (r *Runtime) PullImage(imgName string, allTags bool, signaturePolicyPath string, reportWriter io.Writer) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return ErrRuntimeStopped
	}

	// PullImage copies the image from the source to the destination
	var (
		images []string
	)

	if signaturePolicyPath == "" {
		signaturePolicyPath = r.config.SignaturePolicyPath
	}

	sc := common.GetSystemContext(signaturePolicyPath, "")

	srcRef, err := alltransports.ParseImageName(imgName)
	if err != nil {
		defaultName := DefaultRegistry + imgName
		srcRef2, err2 := alltransports.ParseImageName(defaultName)
		if err2 != nil {
			return errors.Errorf("error parsing image name %q: %v", defaultName, err2)
		}
		srcRef = srcRef2
	}

	splitArr := strings.Split(imgName, ":")
	archFile := splitArr[len(splitArr)-1]

	// supports pulling from docker-archive, oci, and registries
	if srcRef.Transport().Name() == DockerArchive {
		tarSource := tarfile.NewSource(archFile)
		manifest, err := tarSource.LoadTarManifest()
		if err != nil {
			return errors.Errorf("error retrieving manifest.json: %v", err)
		}
		// to pull all the images stored in one tar file
		for i := range manifest {
			if manifest[i].RepoTags != nil {
				images = append(images, manifest[i].RepoTags[0])
			} else {
				// create an image object and use the hex value of the digest as the image ID
				// for parsing the store reference
				newImg, err := srcRef.NewImage(sc)
				if err != nil {
					return err
				}
				defer newImg.Close()
				digest := newImg.ConfigInfo().Digest
				if err := digest.Validate(); err == nil {
					images = append(images, "@"+digest.Hex())
				} else {
					return errors.Wrapf(err, "error getting config info")
				}
			}
		}
	} else if srcRef.Transport().Name() == OCIArchive {
		// retrieve the manifest from index.json to access the image name
		manifest, err := ociarchive.LoadManifestDescriptor(srcRef)
		if err != nil {
			return errors.Wrapf(err, "error loading manifest for %q", srcRef)
		}

		if manifest.Annotations == nil || manifest.Annotations["org.opencontainers.image.ref.name"] == "" {
			return errors.Errorf("error, archive doesn't have a name annotation. Cannot store image with no name")
		}
		images = append(images, manifest.Annotations["org.opencontainers.image.ref.name"])
	} else {
		images = append(images, imgName)
	}

	policy, err := signature.DefaultPolicy(sc)
	if err != nil {
		return err
	}

	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return err
	}
	defer policyContext.Destroy()

	copyOptions := common.GetCopyOptions(reportWriter, signaturePolicyPath, nil, nil, common.SigningOptions{})
	for _, image := range images {
		reference := image
		if srcRef.DockerReference() != nil {
			reference = srcRef.DockerReference().String()
		}
		destRef, err := is.Transport.ParseStoreReference(r.store, reference)
		if err != nil {
			return errors.Errorf("error parsing dest reference name: %v", err)
		}
		if err = cp.Image(policyContext, destRef, srcRef, copyOptions); err != nil {
			return errors.Errorf("error loading image %q: %v", image, err)
		}
	}
	return nil
}

// PushImage pushes the given image to a location described by the given path
func (r *Runtime) PushImage(source string, destination string, options CopyOptions, reportWriter io.Writer) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return ErrRuntimeStopped
	}

	// PushImage pushes the src image to the destination
	//func PushImage(source, destination string, options CopyOptions) error {
	if source == "" || destination == "" {
		return errors.Wrapf(syscall.EINVAL, "source and destination image names must be specified")
	}

	// Get the destination Image Reference
	dest, err := alltransports.ParseImageName(destination)
	if err != nil {
		return errors.Wrapf(err, "error getting destination imageReference for %q", destination)
	}

	signaturePolicyPath := r.config.SignaturePolicyPath
	if options.SignaturePolicyPath != "" {
		signaturePolicyPath = options.SignaturePolicyPath
	}

	policyContext, err := common.GetPolicyContext(signaturePolicyPath)
	if err != nil {
		return errors.Wrapf(err, "Could not get default policy context for signature policy path %q", signaturePolicyPath)
	}
	defer policyContext.Destroy()
	// Look up the image name and its layer, then build the imagePushData from
	// the image
	img, err := r.getImage(source)
	if err != nil {
		return errors.Wrapf(err, "error locating image %q for importing settings", source)
	}
	cd, err := r.ImportCopyDataFromImage(r.imageContext, img.ID, "", "")
	if err != nil {
		return err
	}
	// Give the image we're producing the same ancestors as its source image
	cd.FromImage = cd.Docker.ContainerConfig.Image
	cd.FromImageID = string(cd.Docker.Parent)

	// Prep the layers and manifest for export
	src, err := cd.MakeImageRef(manifest.GuessMIMEType(cd.Manifest), options.Compression, img.Names, img.TopLayer, nil)
	if err != nil {
		return errors.Wrapf(err, "error copying layers and metadata")
	}

	copyOptions := common.GetCopyOptions(reportWriter, signaturePolicyPath, nil, &options.DockerRegistryOptions, options.SigningOptions)

	// Copy the image to the remote destination
	err = cp.Image(policyContext, dest, src, copyOptions)
	if err != nil {
		return errors.Wrapf(err, "Error copying image to the remote destination")
	}
	return nil
}

// TagImage adds a Tag to the given image
func (r *Runtime) TagImage(image *storage.Image, tag string) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return ErrRuntimeStopped
	}

	tags, err := r.store.Names(image.ID)
	if err != nil {
		return err
	}
	for _, key := range tags {
		if key == tag {
			return nil
		}
	}
	tags = append(tags, tag)
	return r.store.SetNames(image.ID, tags)
}

// UntagImage removes a tag from the given image
func (r *Runtime) UntagImage(image *storage.Image, tag string) (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return "", ErrRuntimeStopped
	}

	tags, err := r.store.Names(image.ID)
	if err != nil {
		return "", err
	}
	for i, key := range tags {
		if key == tag {
			tags[i] = tags[len(tags)-1]
			tags = tags[:len(tags)-1]
			break
		}
	}
	if err = r.store.SetNames(image.ID, tags); err != nil {
		return "", err
	}
	return tag, nil
}

// RemoveImage deletes an image from local storage
// Images being used by running containers can only be removed if force=true
func (r *Runtime) RemoveImage(image *storage.Image, force bool) (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return "", ErrRuntimeStopped
	}

	containersWithImage, err := r.getContainersWithImage(image.ID)
	if err != nil {
		return "", errors.Wrapf(err, "error getting containers for image %q", image.ID)
	}
	if len(containersWithImage) > 0 && len(image.Names) <= 1 {
		if force {
			if err := r.removeMultipleContainers(containersWithImage); err != nil {
				return "", err
			}
		} else {
			for _, ctr := range containersWithImage {
				return "", fmt.Errorf("Could not remove image %q (must force) - container %q is using its reference image", image.ID, ctr.ImageID)
			}
		}
	}

	if len(image.Names) > 1 && !force {
		return "", fmt.Errorf("unable to delete %s (must force) - image is referred to in multiple tags", image.ID)
	}
	// If it is forced, we have to untag the image so that it can be deleted
	image.Names = image.Names[:0]

	_, err = r.store.DeleteImage(image.ID, true)
	if err != nil {
		return "", err
	}
	return image.ID, nil
}

// GetImage retrieves an image matching the given name or hash from system
// storage
// If no matching image can be found, an error is returned
func (r *Runtime) GetImage(image string) (*storage.Image, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return nil, ErrRuntimeStopped
	}
	return r.getImage(image)
}

func (r *Runtime) getImage(image string) (*storage.Image, error) {
	var img *storage.Image
	ref, err := is.Transport.ParseStoreReference(r.store, image)
	if err == nil {
		img, err = is.Transport.GetStoreImage(r.store, ref)
	}
	if err != nil {
		img2, err2 := r.store.Image(image)
		if err2 != nil {
			if ref == nil {
				return nil, errors.Wrapf(err, "error parsing reference to image %q", image)
			}
			return nil, errors.Wrapf(err, "unable to locate image %q", image)
		}
		img = img2
	}
	return img, nil
}

// GetImageRef searches for and returns a new types.Image matching the given name or ID in the given store.
func (r *Runtime) GetImageRef(image string) (types.Image, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return nil, ErrRuntimeStopped
	}
	return r.getImageRef(image)

}

func (r *Runtime) getImageRef(image string) (types.Image, error) {
	img, err := r.getImage(image)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to locate image %q", image)
	}
	ref, err := is.Transport.ParseStoreReference(r.store, "@"+img.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing reference to image %q", img.ID)
	}
	imgRef, err := ref.NewImage(nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading image %q", img.ID)
	}
	return imgRef, nil
}

// GetImages retrieves all images present in storage
// Filters can be provided which will determine which images are included in the
// output. Multiple filters are handled by ANDing their output, so only images
// matching all filters are included
func (r *Runtime) GetImages(params *ImageFilterParams, filters ...ImageFilter) ([]*storage.Image, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if !r.valid {
		return nil, ErrRuntimeStopped
	}

	images, err := r.store.Images()
	if err != nil {
		return nil, err
	}

	var imagesFiltered []*storage.Image

	for _, img := range images {
		info, err := r.getImageInspectInfo(img)
		if err != nil {
			return nil, err
		}
		var names []string
		if len(img.Names) > 0 {
			names = img.Names
		} else {
			names = append(names, "<none>")
		}
		for _, name := range names {
			include := true
			if params != nil {
				params.ImageName = name
			}
			for _, filter := range filters {
				include = include && filter(&img, info)
			}

			if include {
				newImage := img
				newImage.Names = []string{name}
				imagesFiltered = append(imagesFiltered, &newImage)
			}
		}
	}

	return imagesFiltered, nil
}

// GetHistory gets the history of an image and information about its layers
func (r *Runtime) GetHistory(image string) ([]ociv1.History, []types.BlobInfo, string, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if !r.valid {
		return nil, nil, "", ErrRuntimeStopped
	}

	img, err := r.getImage(image)
	if err != nil {
		return nil, nil, "", errors.Wrapf(err, "no such image %q", image)
	}

	src, err := r.getImageRef(image)
	if err != nil {
		return nil, nil, "", errors.Wrapf(err, "error instantiating image %q", image)
	}

	oci, err := src.OCIConfig()
	if err != nil {
		return nil, nil, "", err
	}

	return oci.History, src.LayerInfos(), img.ID, nil
}

// ImportImage imports an OCI format image archive into storage as an image
func (r *Runtime) ImportImage(path string) (*storage.Image, error) {
	return nil, ErrNotImplemented
}

// GetImageInspectInfo returns the inspect information of an image
func (r *Runtime) GetImageInspectInfo(image storage.Image) (*types.ImageInspectInfo, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if !r.valid {
		return nil, ErrRuntimeStopped
	}
	return r.getImageInspectInfo(image)
}

func (r *Runtime) getImageInspectInfo(image storage.Image) (*types.ImageInspectInfo, error) {
	img, err := r.getImageRef(image.ID)
	if err != nil {
		return nil, err
	}
	return img.Inspect()
}

// ParseImageFilter takes a set of images and a filter string as input, and returns the libpod.ImageFilterParams struct
func (r *Runtime) ParseImageFilter(imageInput, filter string) (*ImageFilterParams, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if !r.valid {
		return nil, ErrRuntimeStopped
	}

	if filter == "" && imageInput == "" {
		return nil, nil
	}

	var params ImageFilterParams
	params.ImageInput = imageInput

	if filter == "" && imageInput != "" {
		return &params, nil
	}

	images, err := r.store.Images()
	if err != nil {
		return nil, err
	}

	filterStrings := strings.Split(filter, ",")
	for _, param := range filterStrings {
		pair := strings.SplitN(param, "=", 2)
		switch strings.TrimSpace(pair[0]) {
		case "dangling":
			if common.IsValidBool(pair[1]) {
				params.Dangling = pair[1]
			} else {
				return nil, fmt.Errorf("invalid filter: '%s=[%s]'", pair[0], pair[1])
			}
		case "label":
			params.Label = pair[1]
		case "before":
			if img, err := findImageInSlice(images, pair[1]); err == nil {
				info, err := r.GetImageInspectInfo(img)
				if err != nil {
					return nil, err
				}
				params.BeforeImage = info.Created
			} else {
				return nil, fmt.Errorf("no such id: %s", pair[0])
			}
		case "since":
			if img, err := findImageInSlice(images, pair[1]); err == nil {
				info, err := r.GetImageInspectInfo(img)
				if err != nil {
					return nil, err
				}
				params.SinceImage = info.Created
			} else {
				return nil, fmt.Errorf("no such id: %s``", pair[0])
			}
		case "reference":
			params.ReferencePattern = pair[1]
		default:
			return nil, fmt.Errorf("invalid filter: '%s'", pair[0])
		}
	}
	return &params, nil
}

// InfoAndDigestAndSize returns the inspection info and size of the image in the given
// store and the digest of its manifest, if it has one, or "" if it doesn't.
func (r *Runtime) InfoAndDigestAndSize(img storage.Image) (*types.ImageInspectInfo, digest.Digest, int64, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if !r.valid {
		return nil, "", -1, ErrRuntimeStopped
	}

	imgRef, err := r.getImageRef("@" + img.ID)
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading image %q", img.ID)
	}
	defer imgRef.Close()
	return infoAndDigestAndSize(imgRef)
}

func infoAndDigestAndSize(imgRef types.Image) (*types.ImageInspectInfo, digest.Digest, int64, error) {
	imgSize, err := imgRef.Size()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading size of image %q", transports.ImageName(imgRef.Reference()))
	}
	manifest, _, err := imgRef.Manifest()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading manifest for image %q", transports.ImageName(imgRef.Reference()))
	}
	manifestDigest := digest.Digest("")
	if len(manifest) > 0 {
		manifestDigest = digest.Canonical.FromBytes(manifest)
	}
	info, err := imgRef.Inspect()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error inspecting image %q", transports.ImageName(imgRef.Reference()))
	}
	return info, manifestDigest, imgSize, nil
}

// MatchesID returns true if argID is a full or partial match for id
func MatchesID(id, argID string) bool {
	return strings.HasPrefix(argID, id)
}

// MatchesReference returns true if argName is a full or partial match for name
// Partial matches will register only if they match the most specific part of the name available
// For example, take the image docker.io/library/redis:latest
// redis, library/redis, docker.io/library/redis, redis:latest, etc. will match
// But redis:alpine, ry/redis, library, and io/library/redis will not
func MatchesReference(name, argName string) bool {
	if argName == "" {
		return false
	}
	splitName := strings.Split(name, ":")
	// If the arg contains a tag, we handle it differently than if it does not
	if strings.Contains(argName, ":") {
		splitArg := strings.Split(argName, ":")
		return strings.HasSuffix(splitName[0], splitArg[0]) && (splitName[1] == splitArg[1])
	}
	return strings.HasSuffix(splitName[0], argName)
}

// ParseImageNames parses the names we've stored with an image into a list of
// tagged references and a list of references which contain digests.
func ParseImageNames(names []string) (tags, digests []string, err error) {
	for _, name := range names {
		if named, err := reference.ParseNamed(name); err == nil {
			if digested, ok := named.(reference.Digested); ok {
				canonical, err := reference.WithDigest(named, digested.Digest())
				if err == nil {
					digests = append(digests, canonical.String())
				}
			} else {
				if reference.IsNameOnly(named) {
					named = reference.TagNameOnly(named)
				}
				if tagged, ok := named.(reference.Tagged); ok {
					namedTagged, err := reference.WithTag(named, tagged.Tag())
					if err == nil {
						tags = append(tags, namedTagged.String())
					}
				}
			}
		}
	}
	return tags, digests, nil
}

func annotations(manifest []byte, manifestType string) map[string]string {
	annotations := make(map[string]string)
	switch manifestType {
	case ociv1.MediaTypeImageManifest:
		var m ociv1.Manifest
		if err := json.Unmarshal(manifest, &m); err == nil {
			for k, v := range m.Annotations {
				annotations[k] = v
			}
		}
	}
	return annotations
}

func findImageInSlice(images []storage.Image, ref string) (storage.Image, error) {
	for _, image := range images {
		if MatchesID(image.ID, ref) {
			return image, nil
		}
		for _, name := range image.Names {
			if MatchesReference(name, ref) {
				return image, nil
			}
		}
	}
	return storage.Image{}, errors.New("could not find image")
}
