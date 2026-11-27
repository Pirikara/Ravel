# Go local replacement location

Original synthetic fixture. A quoted local replacement location remains a declaration in the SBOM even when the target directory does not exist. A version-specific module replacement stays distinct, and an indirect requirement does not become a direct edge. The scanner neither reads the replacement target nor executes Go for a static manifest scan.
