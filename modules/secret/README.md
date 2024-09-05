# Structure of this directory

1. `additive_two_layered_tagged.go`:
This file is meant for tagging some data into the packets so that
we can measure the size of the packets.
This is used for evaluating the size of packets with various parameters.
2. `additive_two_layered_test.go`:
This file includes various test functions for the additive version
of our system.
3. `additive_two_layered.go`:
This file contains all the functions for implementing the
additive version of our system.
4. `baseline.go`:
This file contains the functions for the single-layered version.
5. `distinguishable.go`:
This file contains the implementation for the distinguishable version -
there is no cryptographic salt used.
6. `hinted_trustees_two_layered.go`:
This file contains all the functions for implementing the
hinted version of our system.
7. `indistinguishable.go`
This file contains the code with multiple layers of secret (more than
two layers).
The code here contains Shamir's secret sharing in each of the layers
such that `n = t` everywhere (of course, it is not the most
optimized version).
8. `parallelized.go`:
This file contains the parallelized version of recovery
for all the versions of our system.
9. `secret_test.go`:
This file contains tests for various building blocks of our system.
10. `thresholded_two_layered_test.go`:
This file includes various test functions for the thresholded version
of our system.
11. `thresholded_two_layered.go`:
This file includes various test functions for the thresholded version
of our system.