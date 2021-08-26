# harbor-scanner-fake

This is a fake scanner used for the performance testing of harbor.

## Build

To run performance tests for the target harbor instance, first ensure you have the prerequisites:

- [Go toolchain](https://go101.org/article/go-toolchain.html)
- Git

Then:

1. Clone this repostiroy
  ```shell
  git clone https://github.com/heww/harbor-scanner-fake
  cd harbor-scanner-fake
  ```

2. Build the binary
  ```shell
  make build
  ```

3. Run
  ```shell
  ./out/bin/harbor-scanner-fake
  ```

## Get the binrary
You can also download the latest pre-build binary file.

```shell
curl -sL $(curl -s https://api.github.com/repos/heww/harbor-scanner-fake/releases/latest | grep 'http.*linux-amd64.tar.gz"' | awk '{print $2}' | sed 's|[\"\,]*||g') | tar -zx
```

## Configuration

When run the scanner, we can privide a yaml file to customize the behavior of the scanner.

```shell
./out/bin/harbor-scanner-fake -c config.yaml
```

Here is a example yaml file

```yaml
--
db:
  total: 10000  # The total count of the vulnerabilities in db
scanner:
  workers: 100 # The count of the scan workers
  skipPulling: true  # Skip pulling the artifact from registry when it's true
  errorRate: 0  # The rate when scan failed for the artifact
  vulnerableRate: 1  # The rate when there are vulnerabilities for the artifact
  vulnerabilitiesPerReport: 100  # The vulnerabilities count in the artifact
  reportGeneratingDuration: 0s  # The duration to generate the scan report after artifact pulled
server:
  address: 0.0.0.0:8080  # The address the scanner listend
  accessLog: true  # The access request will be logged when it's true
  timeout: 0s  # A timeout will be returned when the APIs don't response after this time duration
  delay:
    metadata: 0s  # The dealy duration of the metadata API
    acceptScanRequest: 0s  # The dealy duration of the accept scan request API
    getScanReport: 0s  # The dealy duration of the get scan report API
```
