# Artifact platform independent of host platforms

Original synthetic fixture. Bundler spec records encode their own artifact platform after the version separator. The host platform list does not have to repeat that artifact suffix: generic Darwin, universal Darwin, FreeBSD, and a different Linux libc remain separate from the version. Dot-form gem prereleases remain versions. No package manager or project code runs in the integration test.
