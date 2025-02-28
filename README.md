# pySigma-backend-tracee

This backend utilizes Sigma rules to configure Tracee to apply Sigma rules to containerized environments via eBPF.

# Conversion procedure

1. Choose SigmaRules (Filter by Logsource)
2. Tranlate to GO Signature
3. Build Tracee with Custom Signatures
4. Package to a container
5. Deploy to machine

# Deployment 
Tracee is deployed by an Kubernetes Deamon Set. Every Node runs a Instance of Tracee. See https://aquasecurity.github.io/tracee/v0.8.0/installing/kubernetes/

Change the values.yaml to the custom Tracee Image

# Contributors

The contents of the repository were developed as part of the 5G-FORAN project. The project was funded by the Federal Office for Information Security (BSI) from January 1, 2023 to December 31, 2024, as part of the cybersecurity and digital sovereignty initiatives in 5G/6G communication technologies. Further details can be found at https://www.5g-foran.de