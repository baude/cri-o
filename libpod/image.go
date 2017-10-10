package libpod

import (
	"fmt"
	"io"
	"strings"
	"syscall"
	"os"

	cp "github.com/containers/image/copy"
	dockerarchive "github.com/containers/image/docker/archive"
	"github.com/containers/image/docker/tarfile"
	"github.com/containers/image/manifest"
	ociarchive "github.com/containers/image/oci/archive"
	"github.com/containers/image/signature"
	is "github.com/containers/image/storage"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	"github.com/kubernetes-incubator/cri-o/libpod/common"
	"github.com/kubernetes-incubator/cri-o/libpod/images"
	"github.com/pkg/errors"
	"github.com/containers/image/docker/reference"
	"github.com/containers/image/pkg/sysregistries"
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
	OCIArchive = ociarchive.Transport.Name()
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

func (k *KpodImage ) assembleFqNameTransport() string {
	return fmt.Sprintf("%s%s/%s:%s", k.Transport, k.Registry, k.ImageName, k.Tag)
}

type KpodImage struct {
	Name           string
	fqname         string
	hasImageLocal  bool
	Runtime
	Registry       string
	ImageName      string
	Tag            string
	HasRegistry    bool
	Transport      string
	beenDecomposed bool
	PullName       string
}

func (r *Runtime) NewImage(name string) KpodImage{
	return KpodImage{
		Name: name,
		Runtime: *r,
	}
}

func (k *KpodImage) GetFQName() (string, error)  {
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

func (k *KpodImage) findImageOnRegistry() ( error) {
	searchRegistries, err := GetRegistries()

	if err != nil {
		return errors.Wrapf(err, " the image name '%s' is incomplete.", k.Name)
	}

	for _, searchRegistry := range searchRegistries {
		k.Registry = searchRegistry
		pullRef, err := alltransports.ParseImageName(k.assembleFqNameTransport())
		if err != nil {
			return errors.Errorf("unable to parse '%s'", k.assembleFqName())
		}
		// trying getting this manifest pullRef.DockerReference().String()
		imageSource, err := pullRef.NewImageSource(nil)
		if err != nil {
			return errors.Errorf("unable to create new image source")
		}
		_, _, err = imageSource.GetManifest()
		if err == nil {
			k.fqname = k.assembleFqName()
			return nil
		}
	}
	return errors.Errorf("unable to find image on any configured registries")

}

func (k *KpodImage) Decompose() (error){
	k.beenDecomposed = true
	k.Transport = "docker://"
	var imageError = fmt.Sprintf("unable to parse '%s'\n", k.Name)
	imgRef, err := reference.Parse(k.Name)
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
	if k.HasRegistry {
		k.fqname = k.assembleFqName()
		k.PullName = k.assembleFqName()
		return nil
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

func (k *KpodImage) HasImageLocal() bool{
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
	if err != nil{
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
	k.Runtime.PullImage(k.PullName, false,  k.Runtime.config.SignaturePolicyPath, os.Stdout)
	return nil
}

func GetRegistries() ([]string, error){
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
// Image API

// ImageFilter is a function to determine whether an image is included in
// command output. Images to be outputted are tested using the function. A true
// return will include the image, a false return will exclude it.
type ImageFilter func(*storage.Image) bool

// PullImage pulls an image from configured registries
// By default, only the latest Tag (or a specific Tag if requested) will be
// pulled. If allTags is true, all tags for the requested image will be pulled.
// Signature validation will be performed if the Runtime has been appropriately
// configured
func (r *Runtime) PullImage(imgName string, allTags bool, signaturePolicyPath string, reportWriter io.Writer) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return fmt.Errorf("runtime is not valid")
	}

	// PullImage copies the image from the source to the destination
	var (
		images []string
	)

	if signaturePolicyPath == "" {
		signaturePolicyPath = r.config.SignaturePolicyPath
	}

	sc := common.GetSystemContext(signaturePolicyPath)

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

	policy, err := signature.DefaultPolicy(r.imageContext)
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
		return fmt.Errorf("runtime is not valid")
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
	cd, err := images.ImportCopyDataFromImage(r.store, r.imageContext, img.ID, "", "")
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
		return fmt.Errorf("runtime is not valid")
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

// UntagImage removes a Tag from the given image
func (r *Runtime) UntagImage(image *storage.Image, tag string) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return fmt.Errorf("runtime is not valid")
	}

	tags, err := r.store.Names(image.ID)
	if err != nil {
		return err
	}
	for i, key := range tags {
		if key == tag {
			tags[i] = tags[len(tags)-1]
			tags = tags[:len(tags)-1]
			break
		}
	}
	return r.store.SetNames(image.ID, tags)
}

// RemoveImage deletes an image from local storage
// Images being used by running containers cannot be removed
func (r *Runtime) RemoveImage(image *storage.Image) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return fmt.Errorf("runtime is not valid")
	}

	_, err := r.store.DeleteImage(image.ID, false)
	return err
}

// GetImage retrieves an image matching the given name or hash from system
// storage
// If no matching image can be found, an error is returned
func (r *Runtime) GetImage(image string) (*storage.Image, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.valid {
		return nil, fmt.Errorf("runtime is not valid")
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
		return nil, fmt.Errorf("runtime is not valid")
	}

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
func (r *Runtime) GetImages(filter ...ImageFilter) ([]*storage.Image, error) {
	return nil, ErrNotImplemented
}

// ImportImage imports an OCI format image archive into storage as an image
func (r *Runtime) ImportImage(path string) (*storage.Image, error) {
	return nil, ErrNotImplemented
}
