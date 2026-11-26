# Linux libc platform suffixes

This original fixture reduces a pattern observed in the Zendesk Ruby client
and Rails lockfiles. Their platform lists can name generic Linux targets while
individual artifacts carry `-gnu` or `-musl` qualifiers. Package versions exclude
these qualifiers, platform fields retain them, and RubyGems PURLs preserve them.
The unrelated prerelease version remains intact.
