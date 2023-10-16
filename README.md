# Zklay - Auditable privacy-preserving blockchain

![macOS build](https://github.com/clearmatics/zeth/workflows/zeth-ci-push-build-macos/badge.svg)
![ubuntu build](https://github.com/clearmatics/zeth/workflows/zeth-ci-push-build-ubuntu/badge.svg)

:rotating_light: **WARNING** This project is a Proof of Concept. It is highly inefficient and has not been thoroughly reviewed. Please do not use in production!

**Disclaimer:** This work is inspired from [babyzoe](https://github.com/zcash-hackworks/babyzoe), [Miximus](https://github.com/barryWhiteHat/miximus.git).
It follows and extends the design presented in [zerocash-ethereum](https://github.com/AntoineRondelet/zerocash-ethereum) by adapting some code initially written by [Zcash](https://github.com/zcash/zcash).

:point_right: Check our [paper](https://arxiv.org/pdf/1904.00905.pdf), and the [protocol specifications](https://github.com/clearmatics/zeth-specifications) for more information about Zeth.

:raising_hand: Want to propose a protocol change? Amazing! Please consider writing a [Zeth Protocol Improvement Proposal (ZPIP)](https://github.com/clearmatics/zpips).

## Building and running the project:

:computer: **Warning** This project primarily targets x86_64 Linux and macOS platforms.

### Environment

In order to follow the README below, you will need:
- [Npm](https://www.npmjs.com/get-npm) (at least version `6.9.0`)
- [Node](https://nodejs.org/en/) (recommended version `v10`)
- [Python3](https://www.python.org/downloads/) (at least version `3.9`)
- [Pip](https://pip.pypa.io/en/stable/) (at least version `19.0.2`)
- [JDK11](https://www.oracle.com/java/technologies/downloads/#java11)
- [Openssl](https://www.openssl.org/source/) (at least version `3.0`)
- [GMP](https://gmplib.org/)
- [OMP](https://openmp.llvm.org/)

To use the ZKlay functionality, 2 components are required:
- An Ethereum network (the commands below use a local testnet) to host the ZKlay
  contracts and handle transactions.
- Client tools, which generate all inputs required for a ZKlay operations,
  includes proofs from our modified libsnark library, and transmit transactions to the
  Ethereum network holding the ZKlay contract.


#### Setup and Build:

```bash
# Clone this repository
git clone https://github.com/snp-labs/zklay-dev.git

cd zklay-dev

# Init and update submodule
git submodule init && git submodule update --recursive

# Build libsnark-optimization library

cd depends/libsnark-optimization

make

# Debug version, try running:
make release=no
```


#### Terminal 1: Ethereum testnet

```bash
# Start the Ethereum test net by running the following commands
cd zklay_contracts

# Install dependencies
npm install

# Start a local Ethereum testnet
npm run testrpc
```

#### Terminal 2:

```bash
# Python client
cd client
```

Follow the steps described in the [client README](client/README.md) to run
tests or invoke the ZKlay tools.

## References and useful links

- **BabyZoe:** https://github.com/zcash-hackworks/babyzoe
- **Miximus:** https://github.com/barryWhiteHat/miximus.git
- **SCIPR LAB github:** https://github.com/scipr-lab/
- **Zcash github:** https://github.com/zcash/zcash
- **ZeroCash:** http://zerocash-project.org/
- **Zerocash-Ethereum:** https://github.com/AntoineRondelet/zerocash-ethereum
- **Zeth github:** https://github.com/clearmatics/zeth

## License notices:

### Zcash

```
Copyright (c) 2016-2018 The Zcash developers
Copyright (c) 2009-2018 The Bitcoin Core developers
Copyright (c) 2009-2018 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


The MIT software license (http://www.opensource.org/licenses/mit-license.php)
above applies to the code directly included in this source distribution.
Dependencies downloaded as part of the build process may be covered by other
open-source licenses. For further details see 'contrib/debian/copyright'.


This product includes software developed by the OpenSSL Project for use in the
OpenSSL Toolkit (https://www.openssl.org/). This product includes cryptographic
software written by Eric Young (eay@cryptsoft.com).


Although almost all of the Zcash code is licensed under "permissive" open source
licenses, users and distributors should note that when built using the default
build options, Zcash depends on Oracle Berkeley DB 6.2.x, which is licensed
under the GNU Affero General Public License.
```

### Libsnark

```
The libsnark library is developed by SCIPR Lab (http://scipr-lab.org)
and contributors.

Copyright (c) 2012-2014 SCIPR Lab and contributors (see AUTHORS file).

All files, with the exceptions below, are released under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### Miximus

[barryWhiteHat/miximus GNU General Public License v3.0](https://github.com/barryWhiteHat/miximus/blob/master/LICENSE)
# real-estate
# zkRealEstate
