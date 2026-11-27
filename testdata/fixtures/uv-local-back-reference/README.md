# uv dependency back-reference to a local application

Original synthetic fixture. An optional addon depends on the editable application. The local application remains a valid dependency target alongside an explicitly pinned registry package with the same name. Preserve the cycle, source/version disambiguation, optional group, and declared fork context without selecting an environment or running an installer.
