# Original Composer PHAR fixtures

These small native PHAR archives were generated for Ravel. They contain two
fictional package records and a minimal literal application version, with no
upstream implementation or fixture data. `stored.phar` stores its entries;
`deflated.phar` uses raw DEFLATE. Both carry a SHA-512 checksum footer.

The layout follows the PHP manual's [manifest](https://www.php.net/manual/en/phar.fileformat.phar.php),
[file entries](https://www.php.net/manual/en/phar.fileformat.manifestfile.php), and
[checksum footer](https://www.php.net/manual/en/phar.fileformat.signature.php).
The fixtures can be read by PHP's `Phar::loadPhar` API without executing their
stub or package code.
