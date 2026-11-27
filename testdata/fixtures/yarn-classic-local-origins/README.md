# Yarn Classic explicit local origins

Original synthetic fixture. Link and file selectors retain their declared local source even without a resolved URL. A path containing an @ sign must not alter the package name. Links are local application components and file archives remain packages; neither gets an inferred public npm PURL. The locations do not have to exist: these are lock declarations, and the scanner does not read or execute the target.
