/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sviddisk

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	certsFileMode      = os.FileMode(0o644)
	keyFileMode        = os.FileMode(0o600)
	certsFileName      = "tls.crt"
	keyFileName        = "tls.key"
)

// WriteToDisk takes a X509SVIDResponse, representing a svid message from the Workload API
// and write the certs to disk
func WriteToDisk(svid *x509svid.SVID, dir string) error {
	certsFile := path.Join(dir, certsFileName)
	keyFile := path.Join(dir, keyFileName)

	pemCerts, pemKey, err := svid.Marshal()
	if err != nil {
		return fmt.Errorf("unable to marshal X.509 SVID: %w", err)
	}

	if err := ioutil.WriteFile(certsFile, pemCerts, certsFileMode); err != nil {
		return fmt.Errorf("error writing certs file: %w", err)
	}

	if err := ioutil.WriteFile(keyFile, pemKey, keyFileMode); err != nil {
		return fmt.Errorf("error writing key file: %w", err)
	}

	return nil
}

// waitForCertificates waits up to 3 minutes for the certificate, key, and bundle
// to be on disk.
func WaitForCertificates(dir string) error {
	certsFile := path.Join(dir, certsFileName)
	keyFile := path.Join(dir, keyFileName)

	sleep := 500 * time.Millisecond
	maxRetries := 360
	for i := 1; i <= maxRetries; i++ {
		time.Sleep(sleep)

		if _, err := os.Stat(certsFile); err != nil {
			continue
		}

		if _, err := os.Stat(keyFile); err != nil {
			continue
		}

		return nil
	}

	return errors.New("Timed out waiting for trust bundle")
}

