# Independent workspace roots

This original, reduced fixture models the layout observed in Elastic EUI:
a private monorepo root and a locked workspace application that the root does
not depend on. Scanning includes the root tool, workspace application, and its
library, while excluding the unused external entry. It does not create a
dependency edge between the root and the workspace.
