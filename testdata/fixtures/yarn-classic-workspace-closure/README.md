# Yarn Classic workspace closure

Original synthetic fixture. The root does not depend on its workspace applications. Their dependencies must still be included, while an unrelated lock entry stays excluded. A matching local version links to a workspace; an incompatible range uses the explicit registry lock entry instead. Workspace membership does not add a root dependency. Object-form patterns, globstar, development and optional dependencies, licenses, a child manifest with a string-valued private field, and repository evidence are exercised without running project code.
