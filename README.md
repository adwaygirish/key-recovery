# Key Recovery


The code can be now run for evaluating the computation time and the probability
recovery.

## Building the script
`go build`

## Running the script
The compiled script takes two flags. `-t` or `--type` as the type of
evaluation. Provide the type as `0` if you want to get the computation cost
and provide the type as `1` if you want to evaluate the probability of
key recovery.
The next flag is for the parameter that you want to vary.
Please take a look at `modules/evaluation/evaluate.go` for deciding
what parameter you should use for getting the desired plot.
For instance, if you want to evaluate the worst-case time taken
for key recovery in the additive mode with varying size of the
anonymity set, use the following command:

```
./key_recovery -t 0 -p 0
```

## Cleaning the repository
For cleaning up the results, use: `make clean`

## Repository Structure
- `cmd` is for using the flags with the code. It uses the `cobra` library
for this purpose.

- `modules/configuration` includes the script for dealing with the
`config.yaml` file which contains the default values for running
the experiments.

- `modules/crypto` includes the script for hashes, salts, encryption
and checking matches of various data structures.

- `modules/error` includes the script for storing the results into `.csv`
files. It also includes scripts for storing and loading `.gob` files
for the logarithm table and exponentiation table.

- `modules/evaluation` includes the script for running the code inside
`probability`, `secret`, and `secret_binary_extension`.
This package generates various test cases and runs key recovery
and probability evaluation multiple times (based on the value from
the config file).

- `modules/files` includes various error messages that is provided throughout
the codebase.

- `modules/secret` includes the script that recovers the secret 
from the shares:

    - `baseline.go` contains the code for secret recovery in the baseline
    case - one layer of shares.

    - `additive_two_layered.go` contains the code for additive subsecrets
    and there are no hints.
    This is the code corresponding to **MLSS** in the paper.

    - `thresholded_two_layered.go` contains the code for subsecrets with
    threshold and there are no hints.
    This is the code corresponding to **TMLSS** in the paper.

    - `hinted_trustees_two_layered.go` contains the code for
    additive subsecrets and there are hints.
    The number of hints can be varied in `modules/configuration/config.yaml`.
    This is the code corresponding to **HMLSS** in the paper.

    - `parallelized.go` contains the parallelized version of key recovery
    of the above-mentioned four versions.

- `modules/utils` includes various utility functions that are needed
for running the key recovery.