# Python client to interact with the prover

## Structure of the directory

### `zklay`

```
zklay
 |_ cli
 |_ core
```

This directory contains its backend implementation (`core`) and the code for the client CLI (`cli`).

### `test_commands`

This directory contains a list of useful commands to help run the tests, as well as some minimal testing scenarios acting as integration tests.

### `tests`

The `tests` folder contains the unit tests of the `zklay` package.

## Setup

Ensure that the following are installed:

- Python 3.9 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

Execute the following inside the `client` directory.
```console
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

(It may also be necessary to install solc manually if the `py-solc-x` package
fails to find it. See the instructions below.)

We assume all further commands described here are executed from within the
Python virtualenv.  To enter the virtualenv from a new terminal, re-run
```console
$ source env/bin/activate
```

## Execute a unit test for `zklay` 
```
(env)$ cd TEST
(env)$ zklay test --zksnark GROTH16 --env [ganache|klaytn] --hash [MiMC7|SHA256] --depth [8|16|32]
```

## Note on solc compiler installation

Note that `make setup` will automatically install the solidity compiler in `$HOME/.solc`
(if required) and not in the python virtual environment.

# The `zklay` command line interface

The `zklay` command exposes Zklay operations via a command line interface.  A
brief description is given in this section. 

```console
# Move to TEST directory
cd TEST
```

## Deployment

Deployment compiles and deploys the contracts and initializes them with
appropriate data to create a new instance of the ZKlay. It requires only
an `eth-address` file, where the address has sufficient funds.

```console
# Create a clean directory for the deployer
(env)$ mkdir deployer && cd deployer

# Specify an eth-address file for an (unlocked) Ethereum account on ganache-cli
(env)$ echo 0x.... > eth-address

# Compile and deploy
(env)$ zklay deploy

# Share the instance file and CRS with an auditor and all clients
(env)$ cp zklay-instance <destination>
(env)$ cp ZKlay_CRS_pk.dat <destination>
(env)$ cp ZKlay_CRS_vk.dat <destination>

# Mint tokens for all clients
(env)$ zklay mint --deployer_path <deployer_path> --spender_path <destination> --value <amount>
```

## Auditor setup

To set up an auditor, the auditor should setup file as follows :
```console
#Create a clean auditor directory
$ mkdir auditor && cd auditor

#Sepecfy an eth-address file for an (unlocked) Ethereum acount
$ echo 0x.... > eth-address

#Copy the instance file (received from the deployer)
$ cp <shared-instance-file> zklay-instance
    
#Generate new Zklay auditor secret file
$ zklay audit-key-gen
    
# Share the auditor public address with all clients
$ cp audit-address.pub <destination>
```

## User setup

To set up her client, Alice must setup all client files mentioned above:
```console
# Create a clean client directory (for instance. alice)
$ mkdir alice
$ cd alice

# Specify an eth-address file for an (unlocked) Ethereum account
$ echo 0x.... > eth-address

# Copy the instance file and CRS (received from the deployer) 
$ cp <shared-instance-file> zklay-instance
$ cp <shared-CRS-pk> ZKlay_CRS_pk.dat
$ cp <shared-CRS-vk> ZKlay_CRS_vk.dat
$ cp <shared-audit-pub> audit-address.pub 

# Generate new ZKlay Address (zklay-address.priv, zklay-address.pub)
$ zklay gen-address


With these files in place, `zklay` commands invoked from inside this directory
can perform actions on behalf of Alice.  We call this Alice's *client directory*
below, and assume that all commands are executed in a directory with these
files.
```

## Receiving transactions

The following command scans the blockchain for any new transactions which
generate ZKlay notes intended for the public address `zklay-address.pub` in client directory :

```console
# Check all new blocks for notes addressed to `zklay-address.pub`,
# storing them in the ./notes directory.
(env)$ zklay sync
```

Any notes found are stored in the `./notes` directory as individual files.
These files contain the secret data required to spend the note.

```console
# List all notes received by this client
$ zklay ls-notes
```
lists information about all known notes belonging to the current user.

## Anontransfer command
The `zklay anontransfer` command is used to interact with a deployed ZKlay smart contract instance. The command accepts the following information:

Public Input. ERC20 token value to deposit in the smart contract.

Public Output. ERC20 tokens value to be withdrawn from the smart contract.

Some examples are given below

### Depositing funds
A simple deposit consists of some public input, and the creation of ZKlay notes.

```console
# Deposit 10 ether, creating ZKlay notes owned by Alice
(env)$ zklay anontransfer --v_priv 10 --v_in 10 --rev . --circuit ZKlay
```

### Privately send value to another user

```console
$ zklay anontransfer \
    --v_priv 300 \    # privately send
    --v_in 1000 \.    # public input form sender
    --rev ../Bob \    # to this addr
    --circuit ZKlay
```

### A note on the zklay anontransfer command

As explained above, the zklay anontransfer command can be used to deposit funds on the smart contract, and withdraw funds from the smart contract. A single command can perform all of these in one transaction, which greatly improves the privacy level provided by ZKlay. In fact, no exact information about the meaning of a transaction is ever leaked to an observant attacker.

Here are a example of complex payments allowed by zklay anontransfer:

```console
zklay anontransfer \
    --v_priv 300    
    --v_in 1000
    --v_out 300
    --rev ../bob
    --circuit ZKlay
```
