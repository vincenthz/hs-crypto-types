crypto-types
============

Simple cryptographic basic types (Key, IV, Secret) that are based on a securemem object

secure mem
----------

The secure mem object is a simple piece of allocated memory that have the following properties:

* the memory will be scrubed when the object goes out of scope and is garbage collected.
* a constant time Eq instance.
* a show instance that doesn't show the content on purpose (prevent leaking data).

All necessary functions are exposed to be able to have user defined objects that use the securemem object.

TODO
----

* benchmarks C scrub finalizers against haskell finalizer. specially for small size, the overhead of calling to C might make the finalizer slower.
* check safety of all operations even more carefully. add some kind of unit-tests if possible.
